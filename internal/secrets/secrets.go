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

// getter fetches one secret. Declared so tests need no vault.
type getter interface {
	get(ctx context.Context, vaultURL, name, version string) (string, error)
}

// Resolver dereferences secret references. The zero value is not usable; call
// NewResolver.
type Resolver struct {
	get getter

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
		get:    &azureGetter{clientID: clientID, useDefaultChain: useDefaultChain},
		cached: map[string]string{},
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

	// Deliberately does not name the vault or secret in the error: this runs on
	// a startup path whose failures get logged, and the reference identifies
	// which credential is missing to anyone reading those logs.
	resolved, err := r.get.get(ctx, vaultURL, name, version)
	if err != nil {
		return "", fmt.Errorf("error resolving secret reference: %w", err)
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
