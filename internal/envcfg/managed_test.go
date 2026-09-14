package envcfg

import (
	"testing"

	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/v2"
)

// The running configuration, as the app holds it after the settings table
// loaded and the environment was put back on top.
func runningSMTP(t *testing.T) *koanf.Koanf {
	t.Helper()

	ko := koanf.New(Delim)
	if err := ko.Load(confmap.Provider(map[string]any{
		"smtp": []any{
			map[string]any{
				"host":     "smtp.azurecomm.net",
				"port":     587,
				"password": "from-the-environment",
			},
			map[string]any{
				"uuid":     "bbbb",
				"host":     "second.example",
				"port":     25,
				"password": "stored-in-the-database",
			},
		},
	}, Delim), nil); err != nil {
		t.Fatalf("loading the running config: %v", err)
	}

	return ko
}

// The blocks schema.sql seeds carry no `uuid` — one is only assigned on the
// first settings save — so a deployment configured entirely from the
// environment may never have acquired any. Matching on UUID alone left the
// admin UI's SMTP test dialling the seeded smtp.yoursite.com instead.
func TestManagedElementFallsBackToTheIndex(t *testing.T) {
	block, ok := ManagedElement(runningSMTP(t), []string{"smtp.0.password"}, "smtp", "", 0)
	if !ok {
		t.Fatal("no element for block 0, which the environment manages")
	}

	if got := block.String("host"); got != "smtp.azurecomm.net" {
		t.Errorf("host = %q, want the running value", got)
	}
}

// The UUID is the identity that survives blocks being reordered, so a caller
// carrying one must be answered by it and never by the index beside it.
func TestManagedElementPrefersTheUUID(t *testing.T) {
	keys := []string{"smtp.1.password"}

	block, ok := ManagedElement(runningSMTP(t), keys, "smtp", "bbbb", 0)
	if !ok {
		t.Fatal("no element for the block the UUID names")
	}

	if got := block.String("host"); got != "second.example" {
		t.Errorf("host = %q, want the block the UUID names", got)
	}

	// A UUID nothing matches is not a licence to fall back to the index: the
	// caller named a block, and it is not this one.
	if _, ok := ManagedElement(runningSMTP(t), keys, "smtp", "no-such-uuid", 1); ok {
		t.Error("an unmatched UUID fell through to the index")
	}
}

// Whether the environment manages an element is asked of that element. With
// only `smtp.0.password` set, the second block is still the database's and
// using what was posted is the right thing for it.
func TestManagedElementIsPerElement(t *testing.T) {
	if _, ok := ManagedElement(runningSMTP(t), []string{"smtp.0.password"}, "smtp", "", 1); ok {
		t.Error("block 1 was treated as env-managed on the strength of block 0")
	}
}

// A key naming the section but no element of it — and one naming a different
// section entirely — manages nothing here.
func TestManagedElementIgnoresUnrelatedKeys(t *testing.T) {
	for _, keys := range [][]string{
		{},
		{"smtp"},
		{"smtp.enabled"},
		{"bounce.mailboxes.0.password"},
		// The prefix match must be on the whole index: 0 is not 10.
		{"smtp.10.password"},
	} {
		if _, ok := ManagedElement(runningSMTP(t), keys, "smtp", "", 0); ok {
			t.Errorf("%v made block 0 env-managed", keys)
		}
	}
}

// An index no element occupies must not panic or invent one.
func TestManagedElementIgnoresOutOfRangeIndexes(t *testing.T) {
	keys := []string{"smtp.0.password", "smtp.2.password", "smtp.99.password"}

	for _, index := range []int{-1, 2, 99} {
		if _, ok := ManagedElement(runningSMTP(t), keys, "smtp", "", index); ok {
			t.Errorf("index %d returned an element", index)
		}
	}
}

// A section the running configuration does not have at all.
func TestManagedElementIgnoresUnknownSections(t *testing.T) {
	if _, ok := ManagedElement(runningSMTP(t), []string{"messengers.0.password"}, "messengers", "", 0); ok {
		t.Error("an absent section returned an element")
	}
}
