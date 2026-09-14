package envcfg

import (
	"encoding/json"
	"testing"

	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/v2"
	"github.com/knadh/listmonk/models"
)

// The other tests here describe the settings document by hand, which is how the
// nested-block bug survived: `security.oidc` was written flat in the fixture
// and nested in models.Settings, so the overlay passed its tests and dropped
// every OIDC value in production.
//
// This one round-trips the REAL struct — marshal, overlay, unmarshal — the way
// App.effectiveSettings does, so the shapes cannot drift apart again.
func TestEffectiveAgainstTheRealSettingsStruct(t *testing.T) {
	// What an OIDC-only deployment supplies, all of it from the environment:
	// values in the shape koanf holds them in after Reapply.
	running := koanf.New(Delim)
	if err := running.Load(confmap.Provider(map[string]any{
		"app.root_url":                       "https://news.example.test",
		"privacy.allow_blocklist":            "true",
		"security.oidc.enabled":              "true",
		"security.oidc.provider_url":         "https://login.microsoftonline.com/tid/v2.0",
		"security.oidc.client_id":            "listmonk-prod",
		"security.oidc.client_secret":        "akv:https://v.vault.azure.net/secrets/oidc/1",
		"security.oidc.default_user_role_id": "2",
		"security.oidc.auto_create_emails":   "a@example.test,b@example.test",
		"security.captcha.hcaptcha.enabled":  "true",
		"security.captcha.altcha.complexity": "50000",
		"smtp": []any{
			map[string]any{
				"host":     "smtp.azurecomm.net",
				"port":     "587",
				"username": "sender@list.example.test",
				"password": "akv:https://v.vault.azure.net/secrets/smtp/1",
			},
		},
	}, Delim), nil); err != nil {
		t.Fatalf("loading the running config: %v", err)
	}

	// What the settings table holds: a fresh install nobody has edited, in the
	// shape schema.sql seeds — the SMTP block without a `uuid` among the rest.
	var stored models.Settings
	if err := json.Unmarshal([]byte(`{
		"app.root_url": "http://localhost:9000",
		"privacy.allow_blocklist": false,
		"smtp": [{"host": "smtp.yoursite.com", "port": 25, "password": "password"}]
	}`), &stored); err != nil {
		t.Fatalf("decoding the stored settings: %v", err)
	}

	doc := map[string]any{}
	remarshal(t, stored, &doc)

	Effective(doc, running, []string{
		"app.root_url",
		"privacy.allow_blocklist",
		"security.oidc.enabled",
		"security.oidc.provider_url",
		"security.oidc.client_id",
		"security.oidc.client_secret",
		"security.oidc.default_user_role_id",
		"security.captcha.hcaptcha.enabled",
		"security.captcha.altcha.complexity",
		"smtp.0.host",
		"smtp.0.port",
		"smtp.0.username",
		"smtp.0.password",
		// Not a settings-table key at all: it is read from the config, and the
		// document must come back decodable regardless.
		"security.oidc.auto_create_emails",
	})

	var overlaid models.Settings
	remarshal(t, doc, &overlaid)

	if !overlaid.OIDC.Enabled {
		t.Error("security.oidc.enabled is false after the overlay, which is the bug this is here for")
	}

	if overlaid.OIDC.ClientID != "listmonk-prod" {
		t.Errorf("client_id = %q", overlaid.OIDC.ClientID)
	}

	if overlaid.OIDC.ClientSecret != "akv:https://v.vault.azure.net/secrets/oidc/1" {
		t.Errorf("client_secret = %q", overlaid.OIDC.ClientSecret)
	}

	if !overlaid.OIDC.DefaultUserRoleID.Valid || overlaid.OIDC.DefaultUserRoleID.Int != 2 {
		t.Errorf("default_user_role_id = %+v, want 2", overlaid.OIDC.DefaultUserRoleID)
	}

	if !overlaid.SecurityCaptcha.HCaptcha.Enabled {
		t.Error("security.captcha.hcaptcha.enabled is false after the overlay")
	}

	if overlaid.SecurityCaptcha.Altcha.Complexity != 50000 {
		t.Errorf("altcha.complexity = %d", overlaid.SecurityCaptcha.Altcha.Complexity)
	}

	if overlaid.AppRootURL != "https://news.example.test" || !overlaid.PrivacyAllowBlocklist {
		t.Errorf("flat keys did not survive: root_url=%q blocklist=%v", overlaid.AppRootURL, overlaid.PrivacyAllowBlocklist)
	}

	if got := overlaid.SMTP[0]; got.Host != "smtp.azurecomm.net" || got.Port != 587 ||
		got.Password != "akv:https://v.vault.azure.net/secrets/smtp/1" {
		t.Errorf("smtp[0] = %+v", got)
	}
}

// remarshal is what cmd/settings.go does to get between the struct and the
// dotted document, and back.
func remarshal(t *testing.T, from any, to any) {
	t.Helper()

	b, err := json.Marshal(from)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if err := json.Unmarshal(b, to); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}
