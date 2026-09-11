package envcfg

import (
	"testing"

	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/v2"
)

// Stands in for the settings table, which loads after the environment and
// would otherwise win.
func withSettings(t *testing.T, settings map[string]any) *koanf.Koanf {
	t.Helper()

	ko := koanf.New(Delim)
	if err := ko.Load(confmap.Provider(settings, Delim), nil); err != nil {
		t.Fatalf("seeding settings: %v", err)
	}

	return ko
}

func TestTransform(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{in: "LISTMONK_db__ssl_mode", want: "db.ssl_mode"},
		{in: "LISTMONK_security__oidc__client_secret", want: "security.oidc.client_secret"},
		{in: "LISTMONK_smtp__0__password", want: "smtp.0.password"},
		// Top-level keys are commandline flags, where the separator is a hyphen.
		{in: "LISTMONK_static_dir", want: "static-dir"},
	} {
		if got := transform(tc.in); got != tc.want {
			t.Errorf("transform(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The case the whole package exists for: a secret supplied by the environment
// has to beat the one in the settings table, so that it never needs writing to
// the database to take effect.
func TestReapplyOverridesASettingsTableValue(t *testing.T) {
	t.Setenv("LISTMONK_security__oidc__client_secret", "from-env")

	ko := withSettings(t, map[string]any{
		"security.oidc.client_secret": "from-db",
		"security.oidc.client_id":     "unchanged",
	})

	if err := Reapply(ko); err != nil {
		t.Fatalf("Reapply: %v", err)
	}

	if got := ko.String("security.oidc.client_secret"); got != "from-env" {
		t.Errorf("client_secret = %q, want the env value to win", got)
	}

	if got := ko.String("security.oidc.client_id"); got != "unchanged" {
		t.Errorf("client_id = %q, want the settings value left alone", got)
	}
}

// An indexed key must reach the SLICE, because ko.Slices is how the SMTP
// messengers are built. Unfolded, it lands as a map keyed "0" and is invisible.
func TestReapplyFoldsIndexedKeysIntoTheSlice(t *testing.T) {
	t.Setenv("LISTMONK_smtp__0__password", "from-env")

	ko := withSettings(t, map[string]any{
		"smtp": []any{
			map[string]any{"host": "smtp.example.org", "password": "from-db", "enabled": true},
		},
	})

	if err := Reapply(ko); err != nil {
		t.Fatalf("Reapply: %v", err)
	}

	slices := ko.Slices("smtp")
	if len(slices) != 1 {
		t.Fatalf("smtp has %d elements, want 1 — the env key did not fold into the list", len(slices))
	}

	if got := slices[0].String("password"); got != "from-env" {
		t.Errorf("password = %q, want the env value", got)
	}

	// The rest of the element has to survive, or overriding one field would
	// silently discard the host and disable the sender.
	if got := slices[0].String("host"); got != "smtp.example.org" {
		t.Errorf("host = %q, want the settings value preserved", got)
	}

	if !slices[0].Bool("enabled") {
		t.Error("enabled = false, want the settings value preserved")
	}
}

// A second element the database does not have at all.
func TestReapplyExtendsTheSlice(t *testing.T) {
	t.Setenv("LISTMONK_smtp__1__host", "second.example.org")

	ko := withSettings(t, map[string]any{
		"smtp": []any{map[string]any{"host": "first.example.org"}},
	})

	if err := Reapply(ko); err != nil {
		t.Fatalf("Reapply: %v", err)
	}

	slices := ko.Slices("smtp")
	if len(slices) != 2 {
		t.Fatalf("smtp has %d elements, want 2", len(slices))
	}

	if got := slices[0].String("host"); got != "first.example.org" {
		t.Errorf("element 0 host = %q, want it untouched", got)
	}

	if got := slices[1].String("host"); got != "second.example.org" {
		t.Errorf("element 1 host = %q, want the env value", got)
	}
}

// A nested section, so the section is not assumed to be a single word.
func TestReapplyHandlesANestedIndexedSection(t *testing.T) {
	t.Setenv("LISTMONK_bounce__mailboxes__0__password", "from-env")

	ko := withSettings(t, map[string]any{
		"bounce": map[string]any{
			"mailboxes": []any{map[string]any{"host": "pop.example.org", "password": "from-db"}},
		},
	})

	if err := Reapply(ko); err != nil {
		t.Fatalf("Reapply: %v", err)
	}

	slices := ko.Slices("bounce.mailboxes")
	if len(slices) != 1 {
		t.Fatalf("bounce.mailboxes has %d elements, want 1", len(slices))
	}

	if got := slices[0].String("password"); got != "from-env" {
		t.Errorf("password = %q, want the env value", got)
	}

	if got := slices[0].String("host"); got != "pop.example.org" {
		t.Errorf("host = %q, want the settings value preserved", got)
	}
}

// With nothing in the environment, the settings table has to come through
// untouched — including its lists, which the slice handling must not flatten.
func TestReapplyWithNoEnvChangesNothing(t *testing.T) {
	ko := withSettings(t, map[string]any{
		"app.site_name": "Mailing list",
		"smtp":          []any{map[string]any{"host": "smtp.example.org"}},
	})

	if err := Reapply(ko); err != nil {
		t.Fatalf("Reapply: %v", err)
	}

	if got := ko.String("app.site_name"); got != "Mailing list" {
		t.Errorf("site_name = %q, want it untouched", got)
	}

	slices := ko.Slices("smtp")
	if len(slices) != 1 || slices[0].String("host") != "smtp.example.org" {
		t.Errorf("smtp list was disturbed: %d elements", len(slices))
	}
}
