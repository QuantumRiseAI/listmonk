// Package dbauth provides the non-password Postgres authentication modes.
//
// Azure Database for PostgreSQL can be configured with password
// authentication disabled, accepting only short-lived Microsoft Entra ID
// tokens. On such a server the usual `password=` DSN field cannot work at all,
// and a token cannot simply replace it: tokens last about an hour, so one
// pasted into a DSN at startup would work until the pool next opened a
// connection and then fail for the rest of the process's life.
//
// This package supplies a driver.Connector that mints a token per physical
// connection instead, which database/sql opens rarely rather than per query.
package dbauth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/jmoiron/sqlx"
	"github.com/knadh/listmonk/internal/azcred"
	"github.com/lib/pq"
)

// Values accepted by the `db.auth_mode` setting.
const (
	ModePassword             = "password"
	ModeAzureManagedIdentity = "azure_managed_identity"
)

// The OAuth scope Azure Database for PostgreSQL accepts Entra ID tokens for.
const azurePostgresTokenScope = "https://ossrdbms-aad.database.windows.net/.default"

// A hung token request would otherwise stall a connection attempt
// indefinitely. IMDS normally answers in well under a second, so this only
// bounds failure.
const azureTokenRequestTimeout = 30 * time.Second

// Bounds the startup ping. Generous enough for a token mint plus a TLS
// handshake to a private endpoint, short enough that a dropped route fails the
// revision instead of hanging it.
const connectTimeout = 30 * time.Second

// tokenCredential is the part of azcore.TokenCredential this package needs,
// declared locally so tests can substitute a fake.
type tokenCredential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

// azureTokenConnector mints a fresh Entra ID access token to use as the
// Postgres password each time a new physical connection is opened.
type azureTokenConnector struct {
	// dsn is a libpq key=value DSN with no password field.
	dsn  string
	cred tokenCredential
}

func (c *azureTokenConnector) Connect(ctx context.Context) (driver.Conn, error) {
	// Deliberately a separate context from the one handed to pq below, so the
	// timeout bounds only the token request and not the connection itself.
	tokenCtx, cancel := context.WithTimeout(ctx, azureTokenRequestTimeout)
	token, err := c.cred.GetToken(tokenCtx, policy.TokenRequestOptions{
		Scopes: []string{azurePostgresTokenScope},
	})
	cancel()

	if err != nil {
		return nil, fmt.Errorf("error acquiring Entra ID token for Postgres: %w", err)
	}

	conn, err := pq.NewConnector(c.dsnWithToken(token.Token))
	if err != nil {
		return nil, fmt.Errorf("error building Postgres connector: %w", err)
	}

	return conn.Connect(ctx)
}

func (c *azureTokenConnector) Driver() driver.Driver {
	return &pq.Driver{}
}

// dsnWithToken appends the token as the DSN's password field.
func (c *azureTokenConnector) dsnWithToken(token string) string {
	return c.dsn + " password=" + quoteDSNValue(token)
}

// quoteDSNValue single-quotes a value for a libpq key=value DSN. Entra tokens
// are base64url JWTs and contain nothing needing an escape today, so this
// guards against a future token format rather than fixing the current one.
func quoteDSNValue(v string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
}

// OpenAzureManagedIdentity opens a connection pool that authenticates with
// Entra ID tokens instead of a password. The DSN must carry no password field.
func OpenAzureManagedIdentity(dsn, clientID string, useDefaultChain bool) (*sqlx.DB, error) {
	cred, err := azcred.New(clientID, useDefaultChain)
	if err != nil {
		return nil, fmt.Errorf("error initialising Azure credential: %w", err)
	}

	return openWithCredential(dsn, cred)
}

// openWithCredential is the credential-agnostic half of
// OpenAzureManagedIdentity, split out so tests can inject a credential.
func openWithCredential(dsn string, cred tokenCredential) (*sqlx.DB, error) {
	db := sqlx.NewDb(sql.OpenDB(&azureTokenConnector{dsn: dsn, cred: cred}), "postgres")

	// sql.OpenDB is lazy. Without this a bad credential or an unreachable
	// server would first surface at some later query rather than at startup,
	// unlike the password path, where sqlx.Connect pings.
	//
	// Deadlined, unlike that path: a black-holed server — an NSG dropping
	// rather than refusing — would otherwise hang startup indefinitely, where
	// failing lets Container Apps restart the revision and say so.
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()

		return nil, err
	}

	return db, nil
}

// Encrypting sslmodes. libpq defaults to `prefer` when the field is absent,
// which negotiates TLS but silently falls back to cleartext, so an unset value
// is as unacceptable here as an explicitly weak one.
var encryptingSSLModes = map[string]bool{
	"require":     true,
	"verify-ca":   true,
	"verify-full": true,
}

// RequireEncryptedDSN rejects an assembled DSN whose effective sslmode permits
// an unencrypted connection, which under token authentication is a materially
// worse problem than it is under a password.
//
// The token IS the credential and travels as the DSN password, so a cleartext
// connection puts a bearer token on the wire — replayable by anyone who saw it
// for the rest of its lifetime, against a server that by definition accepts
// tokens. A leaked password, by contrast, is useless against a server with
// password authentication disabled. Upstream's sample ships
// `ssl_mode = "disable"`, so this is a live default rather than a hypothetical.
//
// IT TAKES THE WHOLE DSN, not the ssl_mode field, and that is the point.
// `db.params` is appended to the DSN after the individual fields and libpq is
// last-key-wins, so validating the field alone leaves
//
//	ssl_mode = "require"
//	params   = "sslmode=disable"
//
// passing while the connection is in fact cleartext — defeating this check
// with configuration rather than by evading it.
func RequireEncryptedDSN(dsn string) error {
	mode := effectiveSSLMode(dsn)

	if mode == "" {
		return fmt.Errorf("no sslmode in the database DSN, which libpq treats as %q and allows falling "+
			"back to cleartext; %q requires one of require, verify-ca or verify-full",
			"prefer", ModeAzureManagedIdentity)
	}

	if !encryptingSSLModes[mode] {
		return fmt.Errorf("the database DSN's effective sslmode is %q, which permits an unencrypted "+
			"connection and would put the Entra token on the wire in cleartext; %q requires one of "+
			"require, verify-ca or verify-full (check db.ssl_mode AND db.params, the later wins)",
			mode, ModeAzureManagedIdentity)
	}

	return nil
}

// effectiveSSLMode returns the sslmode libpq would actually use: the LAST one
// in the DSN, since later keys win.
func effectiveSSLMode(dsn string) string {
	mode := ""

	for _, field := range strings.Fields(dsn) {
		key, value, found := strings.Cut(field, "=")
		if found && strings.EqualFold(strings.TrimSpace(key), "sslmode") {
			mode = strings.ToLower(strings.Trim(strings.TrimSpace(value), "'\""))
		}
	}

	return mode
}

// NormaliseMode canonicalises the configured auth mode, defaulting to password
// so an absent setting behaves as it did before this existed.
func NormaliseMode(mode string) (string, error) {
	switch m := strings.ToLower(strings.TrimSpace(mode)); m {
	case "":
		return ModePassword, nil
	case ModePassword, ModeAzureManagedIdentity:
		return m, nil
	default:
		return "", fmt.Errorf("unknown db.auth_mode %q (expected %q or %q)",
			mode, ModePassword, ModeAzureManagedIdentity)
	}
}
