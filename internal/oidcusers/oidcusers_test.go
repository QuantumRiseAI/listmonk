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

	for _, tc := range []struct {
		name  string
		email string
		all   bool
		want  bool
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
	} {
		if got := ShouldCreate(tc.email, tc.all, list); got != tc.want {
			t.Errorf("%s: ShouldCreate(%q, %v) = %v, want %v", tc.name, tc.email, tc.all, got, tc.want)
		}
	}
}

// With no allowlist and auto-create off, nobody is created — which is the
// behaviour every existing install has today.
func TestShouldCreateDefaultsToNobody(t *testing.T) {
	if ShouldCreate("anyone@x.test", false, nil) {
		t.Error("ShouldCreate() = true with no allowlist and auto-create off")
	}
}
