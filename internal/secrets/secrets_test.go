package secrets

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

type fakeGetter struct {
	mu     sync.Mutex
	calls  int
	lastAt struct{ vault, name, version string }
	value  string
	err    error
}

func (f *fakeGetter) get(_ context.Context, vaultURL, name, version string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls++
	f.lastAt.vault, f.lastAt.name, f.lastAt.version = vaultURL, name, version

	return f.value, f.err
}

func newTestResolver(g getter) *Resolver {
	return &Resolver{get: g, cached: map[string]string{}}
}

// The whole design rests on a value with no scheme being untouched, so that
// this is invisible to anyone storing a literal secret.
func TestResolveLeavesALiteralAlone(t *testing.T) {
	g := &fakeGetter{value: "should not be used"}

	got, err := newTestResolver(g).Resolve(context.Background(), "a-real-password")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if got != "a-real-password" {
		t.Errorf("Resolve() = %q, want the literal returned unchanged", got)
	}

	if g.calls != 0 {
		t.Errorf("fetched %d times, want 0 — a literal must not reach the vault", g.calls)
	}
}

func TestResolveDereferencesAReference(t *testing.T) {
	g := &fakeGetter{value: "from-the-vault"}

	got, err := newTestResolver(g).Resolve(context.Background(),
		"akv:https://myvault.vault.azure.net/secrets/smtp-password")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if got != "from-the-vault" {
		t.Errorf("Resolve() = %q, want the vault's value", got)
	}

	if g.lastAt.vault != "https://myvault.vault.azure.net" {
		t.Errorf("vault = %q", g.lastAt.vault)
	}

	if g.lastAt.name != "smtp-password" {
		t.Errorf("name = %q", g.lastAt.name)
	}

	if g.lastAt.version != "" {
		t.Errorf("version = %q, want empty for an unversioned reference", g.lastAt.version)
	}
}

func TestResolveHonoursAPinnedVersion(t *testing.T) {
	g := &fakeGetter{value: "v2"}

	if _, err := newTestResolver(g).Resolve(context.Background(),
		"akv:https://myvault.vault.azure.net/secrets/smtp-password/abc123"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if g.lastAt.version != "abc123" {
		t.Errorf("version = %q, want abc123", g.lastAt.version)
	}
}

// Resolving the same reference repeatedly must not re-authenticate; a campaign
// send would otherwise hit the vault per message.
func TestResolveCachesByReference(t *testing.T) {
	g := &fakeGetter{value: "once"}
	r := newTestResolver(g)

	for range 3 {
		if _, err := r.Resolve(context.Background(),
			"akv:https://myvault.vault.azure.net/secrets/x"); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	}

	if g.calls != 1 {
		t.Errorf("fetched %d times, want 1", g.calls)
	}
}

// A failure has to surface rather than silently yielding an empty credential,
// which would look like an auth failure much later and somewhere else.
func TestResolvePropagatesAFetchFailure(t *testing.T) {
	sentinel := errors.New("forbidden")
	g := &fakeGetter{err: sentinel}

	_, err := newTestResolver(g).Resolve(context.Background(),
		"akv:https://myvault.vault.azure.net/secrets/x")
	if err == nil {
		t.Fatal("Resolve() succeeded with a failing vault")
	}

	if !errors.Is(err, sentinel) {
		t.Errorf("error does not wrap the cause: %v", err)
	}

	// The reference names which credential is missing, and startup errors are
	// logged, so it must not be echoed back.
	if strings.Contains(err.Error(), "myvault") || strings.Contains(err.Error(), "secrets/x") {
		t.Errorf("error leaks the reference: %v", err)
	}
}

func TestResolveRejectsAMalformedReference(t *testing.T) {
	for _, in := range []string{
		"akv:not-a-url",
		"akv:http://myvault.vault.azure.net/secrets/x", // must be https
		"akv:https://myvault.vault.azure.net/x",        // not under /secrets
		"akv:https://myvault.vault.azure.net/secrets/",
		"akv:https://myvault.vault.azure.net/secrets/x/y/z", // too deep
	} {
		g := &fakeGetter{value: "unused"}

		if _, err := newTestResolver(g).Resolve(context.Background(), in); err == nil {
			t.Errorf("Resolve(%q) succeeded, want an error", in)
		}

		if g.calls != 0 {
			t.Errorf("Resolve(%q) reached the vault with a malformed reference", in)
		}
	}
}

func TestIsReference(t *testing.T) {
	for in, want := range map[string]bool{
		"akv:https://v.vault.azure.net/secrets/x":   true,
		"  akv:https://v.vault.azure.net/secrets/x": true,
		"a-real-password":                           false,
		"":                                          false,
		"AKV:https://v.vault.azure.net/secrets/x": false, // case-sensitive on purpose
	} {
		if got := IsReference(in); got != want {
			t.Errorf("IsReference(%q) = %v, want %v", in, got, want)
		}
	}
}
