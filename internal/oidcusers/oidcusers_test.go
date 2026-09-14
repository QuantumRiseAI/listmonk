package oidcusers

import (
	"reflect"
	"testing"
)

// An env var can only ever be one string, so a list has to survive arriving
// that way as well as as a TOML array.
func TestNormalise(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{name: "toml array", in: []string{"a@x.test", "b@x.test"}, want: []string{"a@x.test", "b@x.test"}},
		{name: "comma string", in: []string{"a@x.test,b@x.test"}, want: []string{"a@x.test", "b@x.test"}},
		{name: "spaced", in: []string{" a@x.test , b@x.test "}, want: []string{"a@x.test", "b@x.test"}},
		{name: "cased", in: []string{"A@X.test"}, want: []string{"a@x.test"}},
		{name: "empty entries dropped", in: []string{"a@x.test,,"}, want: []string{"a@x.test"}},
		{name: "nothing", in: nil, want: []string{}},
	} {
		if got := Normalise(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: Normalise(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestShouldCreate(t *testing.T) {
	list := []string{"Allowed@X.test", " other@x.test "}

	yes, no := true, false

	for _, tc := range []struct {
		name     string
		email    string
		verified *bool
		all      bool
		want     bool
	}{
		{name: "on the list", email: "allowed@x.test", want: true},
		{name: "on the list, differently cased", email: "ALLOWED@x.test", want: true},
		{name: "on the list, padded in config", email: "other@x.test", want: true},
		{name: "not on the list", email: "someone@x.test", want: false},

		// The existing switch still wins outright, so this only widens.
		{name: "not on the list but auto-create is on", email: "someone@x.test", all: true, want: true},

		// An empty address must never match an empty or malformed entry.
		{name: "empty address", email: "", want: false},
		{name: "whitespace address", email: "   ", want: false},

		// The provider not saying is permitted; Entra omits the claim for work
		// accounts, so requiring it would refuse every sign-in there.
		{name: "verified absent", email: "allowed@x.test", verified: nil, want: true},
		{name: "verified true", email: "allowed@x.test", verified: &yes, want: true},

		// Explicitly unverified never creates, whichever switch is on: the
		// mechanism rests on the address identifying a person.
		{name: "explicitly unverified", email: "allowed@x.test", verified: &no, want: false},
		{name: "explicitly unverified with auto-create on", email: "anyone@x.test", verified: &no, all: true, want: false},
	} {
		if got := ShouldCreate(tc.email, tc.verified, tc.all, list); got != tc.want {
			t.Errorf("%s: ShouldCreate(%q, %v) = %v, want %v", tc.name, tc.email, tc.all, got, tc.want)
		}
	}
}

// With no allowlist and auto-create off, nobody is created — which is the
// behaviour every existing install has today.
func TestShouldCreateDefaultsToNobody(t *testing.T) {
	if ShouldCreate("anyone@x.test", nil, false, nil) {
		t.Error("ShouldCreate() = true with no allowlist and auto-create off")
	}
}

// The email_verified refusal used to live only in ShouldCreate, so it was asked
// only when the sign-in would create an account. An address the provider marks
// unverified that matches an EXISTING user went straight through to a session —
// the valuable case, and the unguarded one.
func TestUnverified(t *testing.T) {
	yes, no := true, false

	for _, tc := range []struct {
		name     string
		verified *bool
		want     bool
	}{
		// Entra does not emit the claim for work accounts, so absence must not
		// be a refusal or every sign-in there is turned away.
		{"not sent", nil, false},
		{"verified", &yes, false},
		{"explicitly unverified", &no, true},
	} {
		if got := Unverified(tc.verified); got != tc.want {
			t.Errorf("%s: Unverified = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ShouldCreate keeps refusing what Unverified refuses, since the address not
// identifying a person is a reason not to create an account as well as a reason
// not to sign one in.
func TestShouldCreateStillRefusesUnverified(t *testing.T) {
	no := false

	if ShouldCreate("a@example.test", &no, true, nil) {
		t.Error("an unverified address was created under auto_create_users")
	}

	if ShouldCreate("a@example.test", &no, false, []string{"a@example.test"}) {
		t.Error("an unverified address was created off the allowlist")
	}
}
