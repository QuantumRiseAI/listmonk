// Package logintpl exists only to render the admin login template and assert
// what it shows.
//
// It has no production code, which is unusual enough to justify. The login
// template is the one place where the password kill switch is visible to a
// user, and it carries two independent conditions — password login and OIDC —
// that between them produce four configurations. Getting an element into the
// wrong one is invisible to `go build`, invisible to review of a diff, and
// wrong in a direction that matters: a link nested under the OIDC condition
// instead of the password one simultaneously removes password recovery from
// every stock install and keeps advertising a route this fork deliberately
// 404s.
//
// That is not hypothetical. It is what the first attempt at this did, because
// the template has TWO `</form>{{ end }}` sequences — one per condition — and
// a patch anchored on that text matched the wrong one.
package logintpl

import (
	"html/template"
	"path/filepath"
	"strings"
	"testing"
)

// The template calls .L.T and .L.Ts for translation; these stand in.
type stubI18n struct{}

func (stubI18n) T(key string) string { return key }

func (stubI18n) Ts(key string, _ ...string) string { return key }

type loginData struct {
	PasswordEnabled  bool
	OIDCProvider     string
	OIDCProviderLogo string
	Nonce            string
	NextURI          string
	Error            string
}

type page struct {
	RootURL string
	L       stubI18n
	Data    loginData
}

func render(t *testing.T, data loginData) string {
	return renderTemplate(t, "login.html", "admin-login", data)
}

// renderSetup renders the FIRST-TIME SETUP page, which is served in place of
// the login page while no user exists — and therefore has the same two
// conditions to get right.
func renderSetup(t *testing.T, data loginData) string {
	return renderTemplate(t, "login-setup.html", "admin-login-setup", data)
}

func renderTemplate(t *testing.T, file, name string, data loginData) string {
	t.Helper()

	path := filepath.Join("..", "..", "static", "public", "templates", file)

	// header and footer live in other files and are irrelevant here.
	tpl := template.Must(template.New("stubs").Parse(
		`{{ define "header" }}{{ end }}{{ define "footer" }}{{ end }}`))

	tpl = template.Must(tpl.ParseFiles(path))

	var out strings.Builder
	if err := tpl.ExecuteTemplate(&out, name, page{RootURL: "https://example.test", Data: data}); err != nil {
		t.Fatalf("rendering: %v", err)
	}

	return out.String()
}

func TestLoginPageElementsPerConfiguration(t *testing.T) {
	const (
		passwordForm = `action="/admin/login"`
		oidcButton   = `action="/auth/oidc"`
		forgotLink   = `/admin/forgot`
		errorText    = "nobody by that name"
	)

	for _, tc := range []struct {
		name     string
		data     loginData
		password bool
		oidc     bool
		forgot   bool
	}{
		{
			// Stock listmonk. Password recovery must survive this fork.
			name:     "password only",
			data:     loginData{Error: errorText, PasswordEnabled: true},
			password: true, forgot: true,
		},
		{
			name:     "password and OIDC",
			data:     loginData{Error: errorText, PasswordEnabled: true, OIDCProvider: "Microsoft"},
			password: true, oidc: true, forgot: true,
		},
		{
			// What this deployment runs. The forgot route 404s here, so
			// offering it is offering a way in that is not one.
			name: "OIDC only",
			data: loginData{Error: errorText, OIDCProvider: "Microsoft"},
			oidc: true,
		},
		{
			// Refused at startup by assertALoginPathExists, but the template
			// should not invent anything if it is ever reached.
			name: "neither",
			data: loginData{Error: errorText},
		},
	} {
		out := render(t, tc.data)

		for _, check := range []struct {
			what string
			want bool
		}{
			{passwordForm, tc.password},
			{oidcButton, tc.oidc},
			{forgotLink, tc.forgot},
			// Unconditional: an error is only ever set when there is
			// something the person signing in needs to read, and the
			// configuration they are signing in under does not change that.
			{errorText, true},
		} {
			got := strings.Contains(out, check.what)
			if got != check.want {
				t.Errorf("%s: %q present = %v, want %v", tc.name, check.what, got, check.want)
			}
		}
	}
}

// The setup page is served in PLACE of the login page while no user exists, so
// it carries the same two conditions — and got both wrong.
//
// It hardcoded PasswordEnabled and offered no SSO button at all, which meant a
// fresh install with password login disabled and OIDC configured presented a
// username-and-password setup form and nothing else. The first user could only
// be created with a password, on a deployment configured not to allow
// passwords; SSO could not be used until one existed.
func TestSetupPageElementsPerConfiguration(t *testing.T) {
	const (
		setupForm  = `name="password2"`
		oidcButton = `action="/auth/oidc"`
		errorText  = "that username is taken"
	)

	for _, tc := range []struct {
		name     string
		data     loginData
		password bool
		oidc     bool
	}{
		{
			// Stock listmonk: no OIDC, so the password form is the only way to
			// create the first user and must still be there.
			name:     "password only",
			data:     loginData{Error: errorText, PasswordEnabled: true},
			password: true,
		},
		{
			name:     "password and OIDC",
			data:     loginData{Error: errorText, PasswordEnabled: true, OIDCProvider: "Microsoft"},
			password: true, oidc: true,
		},
		{
			// What this fork's deployment runs. The button has to be here or
			// there is no way to create the first user at all.
			name: "OIDC only",
			data: loginData{Error: errorText, OIDCProvider: "Microsoft"},
			oidc: true,
		},
		{
			name: "neither",
			data: loginData{Error: errorText},
		},
	} {
		out := renderSetup(t, tc.data)

		for _, check := range []struct {
			what string
			want bool
		}{
			{setupForm, tc.password},
			{oidcButton, tc.oidc},
			// Unconditional, and the reason it sits outside both blocks: with
			// the password form gone, an error nested inside it is invisible —
			// and the errors this page reports now include the refusal to set
			// up a second time.
			{errorText, true},
		} {
			got := strings.Contains(out, check.what)
			if got != check.want {
				t.Errorf("%s: %q present = %v, want %v", tc.name, check.what, got, check.want)
			}
		}
	}
}
