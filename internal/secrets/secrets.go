// Package secrets resolves secret *references* in configuration values.
//
// listmonk keeps credentials in its `settings` table, which is stored as plain
// JSONB and so is captured by every backup of the database, beyond the reach of
// rotation — rotating a credential does not scrub the copies backups already
// hold. Supplying the credential through the environment instead only moves the
// problem: on a platform that resolves secret references for the container, the
// resolved value becomes readable through the platform's own management API,
// which is typically granted far more widely than the secret store itself.
//
// This resolves the value in-process instead. What is stored — in the settings
// table, in backups, in configuration — is a reference:
//
//	akv:https://myvault.vault.azure.net/secrets/smtp-password
//
// which is a URL rather than a credential. Only the identity the process runs
// as can dereference it, so nothing that can read the database, a backup, or
// the platform's configuration learns the secret.
//
// A value with no scheme prefix is returned unchanged, so this is transparent
// to anyone not using it.
package secrets

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/knadh/listmonk/internal/azcred"
)

// Scheme marks a value as a reference into Azure Key Vault.
const Scheme = "akv:"

// A dereference is a network call on the startup path, so it is bounded. The
// vault is normally single-digit milliseconds away.
const fetchTimeout = 30 * time.Second

// Bounded retry across that window, since the caller treats failure as fatal.
const (
	fetchAttempts = 3
	fetchBackoff  = time.Second
)

// Host suffixes Key Vault is served from, across the public and sovereign
// clouds. A reference to anything else is refused.
var vaultHostSuffixes = []string{
	".vault.azure.net",
	".vault.azure.cn",
	".vault.usgovcloudapi.net",
	".vault.microsoftazure.de",
}

func isVaultHost(host string) bool {
	host = strings.ToLower(host)
	if h, _, found := strings.Cut(host, ":"); found {
		host = h
	}

	for _, suffix := range vaultHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}

	return false
}

// getter fetches one secret. Declared so tests need no vault.
type getter interface {
	get(ctx context.Context, vaultURL, name, version string) (string, error)
}

// Resolver dereferences secret references. The zero value is not usable; call
// NewResolver.
type Resolver struct {
	get getter

	// Injectable so tests do not pay the retry backoff.
	backoff time.Duration

	// Vault clients are safe to reuse and cheap to keep, and a campaign send
	// resolving the same reference repeatedly should not re-authenticate.
	mu     sync.Mutex
	cached map[string]string
}

// NewResolver builds a resolver authenticating as the given identity. It does
// not contact Azure; that happens on the first reference actually resolved, so
// an installation using no references never needs a credential at all.
func NewResolver(clientID string, useDefaultChain bool) *Resolver {
	return &Resolver{
		get:     &azureGetter{clientID: clientID, useDefaultChain: useDefaultChain},
		backoff: fetchBackoff,
		cached:  map[string]string{},
	}
}

// IsReference reports whether a configured value is a reference rather than a
// literal secret.
func IsReference(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), Scheme)
}

// Resolve returns value unchanged unless it is a reference, in which case it
// returns what the reference points at.
func (r *Resolver) Resolve(ctx context.Context, value string) (string, error) {
	value = strings.TrimSpace(value)
	if !IsReference(value) {
		return value, nil
	}

	r.mu.Lock()
	if cached, ok := r.cached[value]; ok {
		r.mu.Unlock()

		return cached, nil
	}
	r.mu.Unlock()

	vaultURL, name, version, err := parse(value)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	// Retried, because the caller treats a failure as fatal and every settings
	// save re-execs the process: a single throttled or 503 response from the
	// vault at the wrong moment would otherwise take the instance down and keep
	// it down. Upstream's other fatal config errors are deterministic; this one
	// depends on a remote service.

	// The error is wrapped as-is, reference and all. An earlier version claimed
	// to keep the vault and secret name out of it, which was both unachievable
	// — azcore's ResponseError prints the request URL — and pointless: a
	// reference is a URL that already sits in the settings table by design. An
	// operator debugging a 403 needs to see which secret it was.
	var resolved string

	for attempt := range fetchAttempts {
		if attempt > 0 {
			select {
			case <-time.After(r.backoff * time.Duration(attempt)):
			case <-ctx.Done():
				return "", fmt.Errorf("error resolving secret reference: %w", ctx.Err())
			}
		}

		resolved, err = r.get.get(ctx, vaultURL, name, version)
		if err == nil {
			break
		}
	}

	if err != nil {
		return "", fmt.Errorf("error resolving secret reference after %d attempts: %w", fetchAttempts, err)
	}

	r.mu.Lock()
	r.cached[value] = resolved
	r.mu.Unlock()

	return resolved, nil
}

// parse splits a reference into the vault, secret name and optional version.
//
//	akv:https://vault.vault.azure.net/secrets/name
//	akv:https://vault.vault.azure.net/secrets/name/version
func parse(reference string) (vaultURL, name, version string, err error) {
	raw := strings.TrimPrefix(strings.TrimSpace(reference), Scheme)

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", fmt.Errorf("malformed secret reference: %w", err)
	}

	if u.Scheme != "https" || u.Host == "" {
		return "", "", "", fmt.Errorf("secret reference must be an https vault URL, got %q", u.Scheme)
	}

	// The host is restricted, not merely required. A reference is stored in a
	// settings field an admin can edit, so without this an admin could point a
	// credential at any host and have the process fetch it from inside the
	// VNet and log the response — blind SSRF with reflection, even though Key
	// Vault's challenge-resource check makes the token itself hard to
	// exfiltrate.
	if !isVaultHost(u.Host) {
		return "", "", "", fmt.Errorf("secret reference host is not a Key Vault")
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "secrets" || parts[1] == "" {
		return "", "", "", fmt.Errorf("secret reference path must be /secrets/<name>[/<version>], got %q", u.Path)
	}

	if len(parts) > 3 {
		return "", "", "", fmt.Errorf("secret reference path must be /secrets/<name>[/<version>], got %q", u.Path)
	}

	if len(parts) == 3 {
		version = parts[2]
	}

	return u.Scheme + "://" + u.Host, parts[1], version, nil
}

// azureGetter fetches from Key Vault with a managed identity.
type azureGetter struct {
	clientID        string
	useDefaultChain bool

	// Built on first use, so an installation using no references never
	// constructs a credential or contacts Azure at all.
	clients sync.Map
}

func (g *azureGetter) get(ctx context.Context, vaultURL, name, version string) (string, error) {
	client, err := g.clientFor(vaultURL)
	if err != nil {
		return "", err
	}

	resp, err := client.GetSecret(ctx, name, version, nil)
	if err != nil {
		return "", err
	}

	if resp.Value == nil {
		return "", fmt.Errorf("vault returned no value")
	}

	return *resp.Value, nil
}

func (g *azureGetter) clientFor(vaultURL string) (*azsecrets.Client, error) {
	if existing, ok := g.clients.Load(vaultURL); ok {
		return existing.(*azsecrets.Client), nil
	}

	cred, err := azcred.New(g.clientID, g.useDefaultChain)
	if err != nil {
		return nil, fmt.Errorf("error initialising Azure credential: %w", err)
	}

	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("error building vault client: %w", err)
	}

	actual, _ := g.clients.LoadOrStore(vaultURL, client)

	return actual.(*azsecrets.Client), nil
}

// Validate reports whether a configured value is usable: either a literal, or
// a reference this package can resolve.
//
// Syntax only, with no network call, so it is safe to run on the write path.
// That is the point of it — a reference is otherwise first parsed by the
// process that respawns after a settings save, where a failure is fatal and
// takes the admin UI with it, leaving SQL as the only way to remove the bad
// value.
func Validate(value string) error {
	if !IsReference(value) {
		return nil
	}

	_, _, _, err := parse(strings.TrimSpace(value))

	return err
}
