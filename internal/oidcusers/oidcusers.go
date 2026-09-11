// Package oidcusers decides whether a first-time SSO sign-in may create a user.
//
// listmonk offers one control today: auto_create_users, on or off. Off means
// every user must be created by hand through the admin UI, which needs a user
// to already exist — so a fresh install with SSO as its only login has no way
// in at all. On means anyone the identity provider will authenticate becomes a
// user, which on a single-tenant Entra registration is every employee.
//
// Neither is what an operator usually wants. The gap between them is an
// allowlist: these people may sign in and be created, nobody else. That is
// bootstrap and access control in one setting, and it is declarable — the list
// lives wherever the deployment is described, rather than as a state somebody
// remembers to turn back off.
package oidcusers

import (
	"strings"
)

// Normalise turns configured values into comparable addresses.
//
// Accepts either a list (a TOML array) or a single comma-separated string,
// because an environment variable can only be the latter: a value supplied as
// LISTMONK_security__oidc__auto_create_emails arrives as one string however it
// was meant.
func Normalise(raw []string) []string {
	out := make([]string, 0, len(raw))

	for _, item := range raw {
		for _, part := range strings.Split(item, ",") {
			if address := strings.ToLower(strings.TrimSpace(part)); address != "" {
				out = append(out, address)
			}
		}
	}

	return out
}

// ShouldCreate reports whether a first-time sign-in by this address may be
// turned into a user.
//
// autoCreateAll is upstream's existing switch and still wins outright when set,
// so this only ever widens what was already allowed.
func ShouldCreate(email string, autoCreateAll bool, allowlist []string) bool {
	if autoCreateAll {
		return true
	}

	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false
	}

	for _, allowed := range Normalise(allowlist) {
		if allowed == email {
			return true
		}
	}

	return false
}
