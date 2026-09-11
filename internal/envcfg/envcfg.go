// Package envcfg owns the LISTMONK_* environment mapping, and can re-apply it
// after the settings table has loaded so that the environment is authoritative
// over the database.
//
// Why that is worth having: almost every listmonk setting lives in a `settings`
// table the admin UI edits, and those load after the config file and the
// environment, so an env-supplied value is overwritten by the database. For
// ordinary settings that is the right way round. For a credential it is not —
// it forces the secret to be written into the database to take effect, where it
// is stored as plain JSONB (`UPDATE settings SET value = ...`) and therefore
// also captured by every backup of the server, beyond the reach of rotation.
//
// With the environment authoritative, a secret can be delivered to the process
// from a secret store and never persisted at all.
//
// The slice handling exists because the plain re-apply is not enough on its
// own. The mapping turns `LISTMONK_smtp__0__password` into the key
// `smtp.0.password`, which koanf unflattens into a MAP keyed "0" rather than a
// list element — so `ko.Slices("smtp")`, which is how the SMTP messengers are
// built, sees nothing, and a naive re-apply would additionally replace a
// database-provided list with that map and break SMTP entirely. Indexed keys
// are therefore folded back into real slices, merged over whatever the database
// supplied for the same index.
package envcfg

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/v2"
)

// Prefix is the environment variable prefix listmonk reads.
const Prefix = "LISTMONK_"

// Delim is the key delimiter koanf is configured with.
const Delim = "."

// Matches a key addressing one element of a list, e.g. `smtp.0.password` or
// `bounce.mailboxes.1.host`. The section is everything before the index, so a
// nested section works without being enumerated.
var indexedKeyRe = regexp.MustCompile(`^(.+)\.(\d+)\.(.+)$`)

// transform maps an environment variable name onto a koanf key.
//
//	LISTMONK_foo__bar  -> foo.bar   (double underscore is the nesting separator)
//	LISTMONK_static_dir -> static-dir
//
// A single underscore becomes a hyphen ONLY in a top-level key, because those
// are commandline flags (static-dir, i18n-dir); nested config keys keep theirs
// (db.ssl_mode).
func transform(s string) string {
	key := strings.ToLower(strings.TrimPrefix(s, Prefix))
	key = strings.Replace(key, "__", Delim, -1)

	if !strings.Contains(key, Delim) {
		key = strings.Replace(key, "_", "-", -1)
	}

	return key
}

// Provider returns the environment provider listmonk loads config from.
func Provider() *env.Env {
	return env.Provider(Prefix, Delim, transform)
}

// Load applies the environment to ko. This is the ordinary startup load, before
// the database is reachable.
func Load(ko *koanf.Koanf) error {
	if err := ko.Load(Provider(), nil); err != nil {
		return fmt.Errorf("error loading config from env: %w", err)
	}

	return nil
}

// Reapply re-applies the environment over ko after the settings table has been
// loaded, so that anything set in the environment wins.
//
// Call it only when the operator has asked for that behaviour: it makes an
// admin-UI edit to any env-set key revert on the next restart, which is the
// point but is surprising if it was not chosen.
func Reapply(ko *koanf.Koanf) error {
	fromEnv := koanf.New(Delim)
	if err := fromEnv.Load(Provider(), nil); err != nil {
		return fmt.Errorf("error reading env: %w", err)
	}

	plain, indexed := partition(fromEnv.All())

	// Snapshot the database's lists BEFORE loading anything, so that merging
	// has something to merge over. Reading them afterwards would read whatever
	// the indexed keys had already turned them into.
	existing := make(map[string][]map[string]any, len(indexed))
	for section := range indexed {
		existing[section] = rawSlices(ko, section)
	}

	if len(plain) > 0 {
		if err := ko.Load(confmap.Provider(plain, Delim), nil); err != nil {
			return fmt.Errorf("error applying env over settings: %w", err)
		}
	}

	// Sorted so the result is deterministic when several sections are indexed.
	sections := make([]string, 0, len(indexed))
	for section := range indexed {
		sections = append(sections, section)
	}

	sort.Strings(sections)

	for _, section := range sections {
		merged, err := mergeIndexed(existing[section], indexed[section])
		if err != nil {
			return fmt.Errorf("error applying env over %q: %w", section, err)
		}

		if err := ko.Load(confmap.Provider(map[string]any{section: merged}, Delim), nil); err != nil {
			return fmt.Errorf("error applying env over %q: %w", section, err)
		}
	}

	return nil
}

// partition splits env keys into ordinary ones and list-element ones.
func partition(all map[string]any) (map[string]any, map[string]map[int]map[string]any) {
	plain := map[string]any{}
	indexed := map[string]map[int]map[string]any{}

	for key, value := range all {
		m := indexedKeyRe.FindStringSubmatch(key)
		if m == nil {
			plain[key] = value

			continue
		}

		section, idx, rest := m[1], m[2], m[3]

		// The regex guarantees digits, so this cannot fail.
		i, _ := strconv.Atoi(idx)

		if indexed[section] == nil {
			indexed[section] = map[int]map[string]any{}
		}

		if indexed[section][i] == nil {
			indexed[section][i] = map[string]any{}
		}

		indexed[section][i][rest] = value
	}

	return plain, indexed
}

// rawSlices reads a section's existing list as plain maps.
func rawSlices(ko *koanf.Koanf, section string) []map[string]any {
	slices := ko.Slices(section)

	out := make([]map[string]any, 0, len(slices))
	for _, s := range slices {
		out = append(out, s.Raw())
	}

	return out
}

// mergeIndexed overlays per-index environment values onto the existing list,
// extending it if the environment addresses an element the database does not
// have. Elements the environment does not mention are returned untouched.
func mergeIndexed(existing []map[string]any, overrides map[int]map[string]any) ([]any, error) {
	size := len(existing)
	for i := range overrides {
		if i+1 > size {
			size = i + 1
		}
	}

	out := make([]any, size)

	for i := range size {
		element := koanf.New(Delim)

		if i < len(existing) && existing[i] != nil {
			if err := element.Load(confmap.Provider(existing[i], Delim), nil); err != nil {
				return nil, fmt.Errorf("element %d: %w", i, err)
			}
		}

		if override, ok := overrides[i]; ok {
			if err := element.Load(confmap.Provider(override, Delim), nil); err != nil {
				return nil, fmt.Errorf("element %d: %w", i, err)
			}
		}

		out[i] = element.Raw()
	}

	return out, nil
}

// Keys returns the settings keys the environment supplies, as the flat paths
// the settings document uses ("app.root_url", "smtp.0.password"), sorted.
//
// It exists so the admin UI can tell the truth. Settings are read from the
// database, but Reapply puts the environment on top of them at load, so a key
// set in the environment is displayed with a value the app is not using. That
// is worse than cosmetic: the SMTP test dials whatever the form holds, so a
// stale form tests a server nobody configured.
func Keys() ([]string, error) {
	fromEnv := koanf.New(Delim)
	if err := fromEnv.Load(Provider(), nil); err != nil {
		return nil, fmt.Errorf("error reading env: %w", err)
	}

	all := fromEnv.All()

	keys := make([]string, 0, len(all))
	for key := range all {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys, nil
}

// Effective overlays, onto a decoded settings document, the values ko holds for
// the given keys.
//
// The document is the settings JSON, whose top-level keys are themselves dotted
// ("app.root_url" is one key, not two levels), except for list sections like
// "smtp" which hold arrays. Those two shapes are the only ones settings use.
func Effective(doc map[string]any, ko *koanf.Koanf, keys []string) {
	// List sections are read through Slices, not by indexed path. koanf holds a
	// list as one value, so ko.Get("smtp.0.host") is nil however the list got
	// there — the same quirk that makes Reapply fold indexed keys into slices in
	// the first place. Cached because a section is usually named by several keys.
	slices := map[string][]*koanf.Koanf{}

	for _, key := range keys {
		if existing, ok := doc[key]; ok {
			doc[key] = valueLike(existing, ko, key)
			continue
		}

		m := indexedKeyRe.FindStringSubmatch(key)
		if m == nil {
			// A key the settings document does not carry. Config-file-only
			// settings such as `app.address` and the whole `db` block live in
			// the environment and never in the database, so this is ordinary.
			continue
		}

		section, field := m[1], m[3]

		index, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}

		list, ok := doc[section].([]any)
		if !ok || index >= len(list) {
			continue
		}

		element, ok := list[index].(map[string]any)
		if !ok {
			continue
		}

		if _, ok := slices[section]; !ok {
			slices[section] = ko.Slices(section)
		}

		running := slices[section]
		if index >= len(running) {
			continue
		}

		element[field] = valueLike(element[field], running[index], field)
	}
}

// valueLike reads key from ko as the type the settings document already
// holds there.
//
// Every environment value is a string, so a plain Get puts "true" where the
// settings struct has a bool and unmarshalling the document back fails on the
// first such key. The stored value is the only statement of the intended type
// available here, which is enough: it came from the same struct.
func valueLike(existing any, ko *koanf.Koanf, key string) any {
	switch existing.(type) {
	case bool:
		return ko.Bool(key)
	case float64:
		return ko.Float64(key)
	case []any:
		return list(ko, key)
	case string:
		return ko.String(key)
	default:
		// null, or a nested object. Nothing delivers one of those by
		// environment today, and Effective's caller treats a document it
		// cannot decode as a reason to show the stored settings instead.
		return ko.Get(key)
	}
}

// list reads key as a list, accepting the single comma-separated string an
// environment variable is limited to expressing.
//
// koanf does not split such a value, so Strings() on it yields nothing. The
// same convention is read the same way at runtime by oidcusers.Normalise, which
// exists for this reason.
func list(ko *koanf.Koanf, key string) []string {
	if raw, ok := ko.Get(key).([]any); ok {
		out := make([]string, 0, len(raw))
		for _, element := range raw {
			out = append(out, fmt.Sprintf("%v", element))
		}

		return out
	}

	out := []string{}
	for _, part := range strings.Split(ko.String(key), ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}

	return out
}
