package azcred

import "testing"

// ManagedIdentityCredential does not read AZURE_CLIENT_ID itself, and the
// surrounding infrastructure sets exactly that variable to select an identity,
// so the fallback is what stops the app authenticating as nothing.
func TestResolveClientID(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", "from-env")

	if got := ResolveClientID("from-config"); got != "from-config" {
		t.Errorf("ResolveClientID() = %q, want the config value to win", got)
	}

	if got := ResolveClientID(""); got != "from-env" {
		t.Errorf("ResolveClientID() = %q, want the env fallback", got)
	}

	t.Setenv("AZURE_CLIENT_ID", "  padded  ")

	if got := ResolveClientID(""); got != "padded" {
		t.Errorf("ResolveClientID() = %q, want the env value trimmed", got)
	}

	t.Setenv("AZURE_CLIENT_ID", "")

	if got := ResolveClientID(""); got != "" {
		t.Errorf("ResolveClientID() = %q, want empty when neither is set", got)
	}
}
