package envcfg

import (
	"reflect"
	"testing"

	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/v2"
)

// The running configuration as Reapply receives it: the config file and then
// the settings table, with the environment still to be put back on top.
func storedConfig(t *testing.T) *koanf.Koanf {
	t.Helper()

	ko := koanf.New(Delim)
	if err := ko.Load(confmap.Provider(map[string]any{
		"smtp": []any{
			map[string]any{"host": "relay-a.example", "password": "a"},
			map[string]any{"host": "relay-b.example", "password": "b"},
		},
		"privacy.domain_blocklist": []any{"old.test"},
		"upload.extensions":        []any{"jpg", "png"},
		"app.site_name":            "Example, Inc",
	}, Delim), nil); err != nil {
		t.Fatalf("loading the stored config: %v", err)
	}

	return ko
}

// A key that indexes twice used to take the whole enclosing list with it: the
// greedy section match made `smtp.0.email_headers.0.x_trace` parse as section
// `smtp.0.email_headers`, and loading that replaced the `smtp` LIST with a map.
// Every SMTP server disappeared and no campaign could send, silently.
func TestReapplySurvivesATwiceIndexedKey(t *testing.T) {
	t.Setenv("LISTMONK_smtp__0__email_headers__0__x_trace", "1")

	ko := storedConfig(t)
	if err := Reapply(ko); err != nil {
		t.Fatalf("Reapply: %v", err)
	}

	blocks := ko.Slices("smtp")
	if len(blocks) != 2 {
		t.Fatalf("smtp has %d blocks, want the 2 that were stored (value is %#v)", len(blocks), ko.Get("smtp"))
	}

	if got := blocks[0].String("host"); got != "relay-a.example" {
		t.Errorf("smtp.0.host = %q, want it left alone", got)
	}
}

// The first index is the one that names the element, so an ordinary override
// alongside a twice-indexed key still applies.
func TestReapplyStillMergesAlongsideIt(t *testing.T) {
	t.Setenv("LISTMONK_smtp__0__email_headers__0__x_trace", "1")
	t.Setenv("LISTMONK_smtp__1__password", "from-the-environment")

	ko := storedConfig(t)
	if err := Reapply(ko); err != nil {
		t.Fatalf("Reapply: %v", err)
	}

	blocks := ko.Slices("smtp")
	if len(blocks) != 2 {
		t.Fatalf("smtp has %d blocks, want 2", len(blocks))
	}

	if got := blocks[1].String("password"); got != "from-the-environment" {
		t.Errorf("smtp.1.password = %q", got)
	}

	if got := blocks[1].String("host"); got != "relay-b.example" {
		t.Errorf("smtp.1.host = %q, want the stored value kept", got)
	}
}

// An environment variable can only be one string and koanf does not split it,
// so a list setting overridden from the environment read back EMPTY — uploads
// rejecting every extension, a blocklist blocking nothing, notifications going
// nowhere, none of it with an error.
func TestReapplySplitsListSettings(t *testing.T) {
	t.Setenv("LISTMONK_privacy__domain_blocklist", "spam.test, junk.test")
	t.Setenv("LISTMONK_upload__extensions", "jpg,pdf")

	ko := storedConfig(t)
	if err := Reapply(ko); err != nil {
		t.Fatalf("Reapply: %v", err)
	}

	if got := ko.Strings("privacy.domain_blocklist"); !reflect.DeepEqual(got, []string{"spam.test", "junk.test"}) {
		t.Errorf("domain_blocklist = %#v", got)
	}

	if got := ko.Strings("upload.extensions"); !reflect.DeepEqual(got, []string{"jpg", "pdf"}) {
		t.Errorf("upload.extensions = %#v", got)
	}
}

// Splitting is decided by what the setting already holds, not by whether the
// value contains a comma, so a plain string setting keeps its commas.
func TestReapplyLeavesStringSettingsWhole(t *testing.T) {
	t.Setenv("LISTMONK_app__site_name", "Example, Inc")

	ko := storedConfig(t)
	if err := Reapply(ko); err != nil {
		t.Fatalf("Reapply: %v", err)
	}

	if got := ko.String("app.site_name"); got != "Example, Inc" {
		t.Errorf("app.site_name = %q, want the comma kept", got)
	}
}
