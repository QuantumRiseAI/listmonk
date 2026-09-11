package envcfg

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/v2"
)

// The settings document is the JSON shape models.Settings marshals to: top
// level keys are themselves dotted, and list sections hold arrays.
func settingsDoc() map[string]any {
	return map[string]any{
		"app.root_url":  "http://localhost:9000",
		"app.site_name": "listmonk",
		"smtp": []any{
			map[string]any{
				"uuid":     "aaaa",
				"host":     "smtp.yoursite.com",
				"username": "",
				"password": "",
			},
			map[string]any{
				"uuid": "bbbb",
				"host": "second.example",
			},
		},
	}
}

func TestEffectiveOverlaysWhatIsRunning(t *testing.T) {
	ko := koanf.New(Delim)

	// What the app is actually running with, after the environment was put back
	// on top of the settings table.
	if err := ko.Load(confmap.Provider(map[string]any{
		"app.root_url": "https://news.example.test",
		"smtp": []any{
			map[string]any{
				"uuid":     "aaaa",
				"host":     "smtp.azurecomm.net",
				"username": "sender@list.example.test",
				"password": "akv:https://v.vault.azure.net/secrets/p/1",
			},
		},
	}, Delim), nil); err != nil {
		t.Fatalf("loading: %v", err)
	}

	doc := settingsDoc()

	Effective(doc, ko, []string{
		"app.root_url",
		"smtp.0.host",
		"smtp.0.username",
		"smtp.0.password",
		// Set in the environment but never stored in the settings table. The
		// whole `db` block and `app.address` are like this, so a key the
		// document does not carry must be skipped rather than invented.
		"db.host",
	})

	if got := doc["app.root_url"]; got != "https://news.example.test" {
		t.Errorf("root_url = %v, want the running value", got)
	}

	// Untouched, because the environment does not supply it.
	if got := doc["app.site_name"]; got != "listmonk" {
		t.Errorf("site_name = %v, want the stored value", got)
	}

	if _, ok := doc["db.host"]; ok {
		t.Error("db.host was added to the settings document, which does not carry it")
	}

	list, ok := doc["smtp"].([]any)
	if !ok {
		t.Fatalf("smtp is %T, want a list", doc["smtp"])
	}

	first, _ := list[0].(map[string]any)
	for _, tc := range []struct{ field, want string }{
		{"host", "smtp.azurecomm.net"},
		{"username", "sender@list.example.test"},
		{"password", "akv:https://v.vault.azure.net/secrets/p/1"},
	} {
		if got := first[tc.field]; got != tc.want {
			t.Errorf("smtp.0.%s = %v, want %q", tc.field, got, tc.want)
		}
	}

	// The second block is not managed, and there is no second element in the
	// running config to read. It must survive rather than be cleared.
	second, _ := list[1].(map[string]any)
	if got := second["host"]; got != "second.example" {
		t.Errorf("smtp.1.host = %v, want it left alone", got)
	}
}

// An index the running config does not have must not panic or fabricate one.
func TestEffectiveIgnoresOutOfRangeIndexes(t *testing.T) {
	ko := koanf.New(Delim)

	doc := settingsDoc()
	before := doc["smtp"].([]any)[1].(map[string]any)["host"]

	Effective(doc, ko, []string{"smtp.9.host", "smtp.notanumber.host"})

	if got := doc["smtp"].([]any)[1].(map[string]any)["host"]; got != before {
		t.Errorf("smtp.1.host = %v, want %v", got, before)
	}
}

func TestKeysReportsWhatTheEnvironmentSupplies(t *testing.T) {
	for k, v := range map[string]string{
		"LISTMONK_app__root_url":     "https://news.example.test",
		"LISTMONK_smtp__0__password": "akv:https://v.vault.azure.net/secrets/p/1",
	} {
		t.Setenv(k, v)
	}

	// Asserted as a subset rather than an exact list: the ambient environment
	// may hold LISTMONK_* of its own.
	keys, err := Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}

	want := map[string]bool{"app.root_url": true, "smtp.0.password": true}
	for _, key := range keys {
		delete(want, key)
	}

	if len(want) > 0 {
		t.Errorf("Keys() = %v, missing %v", keys, reflect.ValueOf(want).MapKeys())
	}
}

// Every environment value is a string, so overlaying one onto a setting the
// struct declares as a bool or a number has to convert rather than copy.
//
// The un-converted version failed in production, on the first such key the
// decoder happened to reach:
//
//	json: cannot unmarshal string into Go struct field
//	Settings.privacy.allow_blocklist of type bool
func TestEffectiveConvertsToTheStoredType(t *testing.T) {
	ko := koanf.New(Delim)

	// As the environment provider yields them: strings, every one.
	if err := ko.Load(confmap.Provider(map[string]any{
		"privacy.allow_blocklist": "true",
		"app.notify_emails":       "a@example.test,b@example.test",
		"smtp": []any{
			map[string]any{"port": "587", "host": "smtp.azurecomm.net"},
		},
	}, Delim), nil); err != nil {
		t.Fatalf("loading: %v", err)
	}

	doc := map[string]any{
		"privacy.allow_blocklist": false,
		"app.notify_emails":       []any{"old@example.test"},
		"smtp": []any{
			map[string]any{"port": float64(25), "host": "smtp.yoursite.com"},
		},
	}

	Effective(doc, ko, []string{
		"privacy.allow_blocklist",
		"app.notify_emails",
		"smtp.0.port",
		"smtp.0.host",
	})

	if got := doc["privacy.allow_blocklist"]; got != true {
		t.Errorf("allow_blocklist = %#v, want the bool true", got)
	}

	if got := doc["smtp"].([]any)[0].(map[string]any)["port"]; got != float64(587) {
		t.Errorf("smtp.0.port = %#v, want a number", got)
	}

	if got := doc["smtp"].([]any)[0].(map[string]any)["host"]; got != "smtp.azurecomm.net" {
		t.Errorf("smtp.0.host = %#v", got)
	}

	// The whole point: the document has to decode back into the typed struct.
	var into struct {
		AllowBlocklist bool     `json:"privacy.allow_blocklist"`
		NotifyEmails   []string `json:"app.notify_emails"`
		SMTP           []struct {
			Port int `json:"port"`
		} `json:"smtp"`
	}

	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if err := json.Unmarshal(b, &into); err != nil {
		t.Fatalf("decoding the overlaid document: %v", err)
	}

	if !into.AllowBlocklist || into.SMTP[0].Port != 587 {
		t.Errorf("decoded = %+v", into)
	}

	if len(into.NotifyEmails) != 2 {
		t.Errorf("notify_emails = %v, want the env list split", into.NotifyEmails)
	}
}
