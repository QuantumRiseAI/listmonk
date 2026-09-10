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
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/jmoiron/sqlx"
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

// newAzureCredential builds the credential used to mint database tokens.
// Managed identity is the default and the broad chain is opt-in.
func newAzureCredential(clientID string, useDefaultChain bool) (tokenCredential, error) {
	if useDefaultChain {
		// DefaultAzureCredential walks a broad chain that includes ambient
		// AZURE_* environment variables and a developer's local `az login`.
		// That is convenient on a laptop but wrong as a default for a database
		// credential: a stray AZURE_CLIENT_SECRET in the environment would
		// silently outrank the intended managed identity, and a developer
		// running the binary would connect as themselves rather than as the
		// app. So the narrow credential is the default and this one has to be
		// asked for by name.
		//
		// DefaultAzureCredentialOptions has no field for a user-assigned
		// identity, so on this path the id is read from AZURE_CLIENT_ID in the
		// environment; db.azure_client_id applies to managed identity only.
		return azidentity.NewDefaultAzureCredential(nil)
	}

	opts := &azidentity.ManagedIdentityCredentialOptions{}
	if clientID != "" {
		opts.ID = azidentity.ClientID(clientID)
	}

	// With no ID set, this resolves the host's system-assigned identity.
	return azidentity.NewManagedIdentityCredential(opts)
}

// OpenAzureManagedIdentity opens a connection pool that authenticates with
// Entra ID tokens instead of a password. The DSN must carry no password field.
func OpenAzureManagedIdentity(dsn, clientID string, useDefaultChain bool) (*sqlx.DB, error) {
	cred, err := newAzureCredential(clientID, useDefaultChain)
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
	if err := db.Ping(); err != nil {
		db.Close()

		return nil, err
	}

	return db, nil
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
