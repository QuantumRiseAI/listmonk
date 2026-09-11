package dbauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// A port nothing listens on, so a connection attempt fails immediately once
// the token has been minted. These tests cover the credential path, not pq.
const unreachableDSN = "host=127.0.0.1 port=1 user=listmonk dbname=listmonk sslmode=disable"

type fakeCredential struct {
	token  string
	err    error
	calls  int
	scopes []string
}

func (f *fakeCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.calls++
	f.scopes = append(f.scopes, opts.Scopes...)

	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}

	return azcore.AccessToken{Token: f.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestNormaliseMode(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: ModePassword},
		{in: "password", want: ModePassword},
		{in: "PASSWORD", want: ModePassword},
		{in: "azure_managed_identity", want: ModeAzureManagedIdentity},
		{in: "  Azure_Managed_Identity  ", want: ModeAzureManagedIdentity},
		{in: "azure", wantErr: true},
		{in: "managed_identity", wantErr: true},
	} {
		got, err := NormaliseMode(tc.in)

		if tc.wantErr {
			if err == nil {
				t.Errorf("NormaliseMode(%q): expected an error, got %q", tc.in, got)
			}

			continue
		}

		if err != nil {
			t.Errorf("NormaliseMode(%q): unexpected error: %v", tc.in, err)

			continue
		}

		if got != tc.want {
			t.Errorf("NormaliseMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestQuoteDSNValue(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{in: "eyJhbGci.eyJhdWQi.sig-_x", want: "'eyJhbGci.eyJhdWQi.sig-_x'"},
		{in: "", want: "''"},
		{in: `has'quote`, want: `'has\'quote'`},
		{in: `has\backslash`, want: `'has\\backslash'`},
	} {
		if got := quoteDSNValue(tc.in); got != tc.want {
			t.Errorf("quoteDSNValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The token must land in the DSN as a quoted password so that a value
// containing a DSN metacharacter cannot terminate the field early.
func TestDSNWithToken(t *testing.T) {
	c := &azureTokenConnector{dsn: "host=db user=listmonk-mi"}

	if got, want := c.dsnWithToken("tok"), "host=db user=listmonk-mi password='tok'"; got != want {
		t.Errorf("dsnWithToken() = %q, want %q", got, want)
	}
}

func TestRequireEncryptedSSLMode(t *testing.T) {
	for _, tc := range []struct {
		in      string
		wantErr bool
	}{
		// Unset is `prefer` to libpq, which falls back to cleartext.
		{in: "", wantErr: true},
		{in: "disable", wantErr: true},
		{in: "allow", wantErr: true},
		{in: "prefer", wantErr: true},
		{in: "require"},
		{in: "REQUIRE"},
		{in: "  verify-ca  "},
		{in: "verify-full"},
	} {
		err := RequireEncryptedSSLMode(tc.in)

		if tc.wantErr && err == nil {
			t.Errorf("RequireEncryptedSSLMode(%q): expected an error", tc.in)
		}

		if !tc.wantErr && err != nil {
			t.Errorf("RequireEncryptedSSLMode(%q): unexpected error: %v", tc.in, err)
		}
	}
}

// The scope is what makes the token usable against Postgres rather than
// against some other Azure resource, so it is asserted explicitly.
func TestConnectRequestsThePostgresScope(t *testing.T) {
	cred := &fakeCredential{token: "tok"}
	c := &azureTokenConnector{dsn: unreachableDSN, cred: cred}

	// Deadlined so that a sandbox black-holing this address fails the test
	// rather than hanging it to the package timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Expected to fail at the dial, having already minted a token.
	if _, err := c.Connect(ctx); err == nil {
		t.Fatal("Connect() unexpectedly succeeded against an unreachable server")
	} else if strings.Contains(err.Error(), "Entra ID token") {
		t.Fatalf("Connect() failed in the token step rather than the dial: %v", err)
	}

	if cred.calls != 1 {
		t.Errorf("GetToken called %d times, want 1", cred.calls)
	}

	if len(cred.scopes) != 1 || cred.scopes[0] != azurePostgresTokenScope {
		t.Errorf("GetToken scopes = %v, want [%s]", cred.scopes, azurePostgresTokenScope)
	}
}

func TestConnectPropagatesTokenError(t *testing.T) {
	sentinel := errors.New("no managed identity endpoint")
	c := &azureTokenConnector{dsn: unreachableDSN, cred: &fakeCredential{err: sentinel}}

	_, err := c.Connect(context.Background())
	if err == nil {
		t.Fatal("Connect() unexpectedly succeeded with a failing credential")
	}

	if !errors.Is(err, sentinel) {
		t.Errorf("Connect() error does not wrap the credential error: %v", err)
	}

	if !strings.Contains(err.Error(), "Entra ID token") {
		t.Errorf("Connect() error does not say the token step failed: %v", err)
	}
}

// openWithCredential must ping, so that a credential or connectivity problem
// is a startup failure rather than a surprise at the first query.
func TestOpenWithCredentialPingsBeforeReturning(t *testing.T) {
	cred := &fakeCredential{token: "tok"}

	db, err := openWithCredential(unreachableDSN, cred)
	if err == nil {
		db.Close()
		t.Fatal("openWithCredential() returned a pool for an unreachable server")
	}

	if cred.calls == 0 {
		t.Error("openWithCredential() returned before attempting a connection")
	}
}
