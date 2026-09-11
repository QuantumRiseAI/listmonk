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
	t.Helper()

	path := filepath.Join("..", "..", "static", "public", "templates", "login.html")

	// header and footer live in other files and are irrelevant here.
	tpl := template.Must(template.New("stubs").Parse(
		`{{ define "header" }}{{ end }}{{ define "footer" }}{{ end }}`))

	tpl = template.Must(tpl.ParseFiles(path))

	var out strings.Builder
	if err := tpl.ExecuteTemplate(&out, "admin-login", page{RootURL: "https://example.test", Data: data}); err != nil {
		t.Fatalf("rendering: %v", err)
	}

	return out.String()
}

func TestLoginPageElementsPerConfiguration(t *testing.T) {
	const (
		passwordForm = `action="/admin/login"`
		oidcButton   = `action="/auth/oidc"`
		forgotLink   = `/admin/forgot`
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
			data:     loginData{PasswordEnabled: true},
			password: true, forgot: true,
		},
		{
			name:     "password and OIDC",
			data:     loginData{PasswordEnabled: true, OIDCProvider: "Microsoft"},
			password: true, oidc: true, forgot: true,
		},
		{
			// What this deployment runs. The forgot route 404s here, so
			// offering it is offering a way in that is not one.
			name: "OIDC only",
			data: loginData{OIDCProvider: "Microsoft"},
			oidc: true,
		},
		{
			// Refused at startup by assertALoginPathExists, but the template
			// should not invent anything if it is ever reached.
			name: "neither",
			data: loginData{},
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
		} {
			got := strings.Contains(out, check.what)
			if got != check.want {
				t.Errorf("%s: %q present = %v, want %v", tc.name, check.what, got, check.want)
			}
		}
	}
}
