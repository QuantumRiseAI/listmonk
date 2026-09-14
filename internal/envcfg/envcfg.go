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

// Flat settings keys that `omitempty` drops from the document when what is
// stored is empty, so that their absence has to be read as "stored empty"
// rather than "not a settings key".
//
// Enumerated because nothing in the document distinguishes them. The list
// elements' passwords are tagged the same way in models.Settings but are
// reached structurally, by applyIndexed, and need no entry here.
var omitemptyKeys = map[string]bool{
	"upload.s3.aws_secret_access_key": true,
}

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

// ManagedElement returns the running configuration of the element of a list
// section — an SMTP block, a bounce mailbox — that uuid or index names, but
// only when the environment supplies at least one of THAT element's fields.
//
// It answers "may I show or use the running values here instead of the ones
// posted to me", which is a question about one element: with only
// `smtp.0.password` in the environment, the second block is still the
// database's.
//
// Identified by UUID when the caller has one, because the UUID is the only
// identity an element keeps across being reordered or removed in the admin UI,
// and the environment overrides fields within an element and never its UUID.
//
// There is not always one. schema.sql seeds the default SMTP blocks with no
// `uuid` field at all and one is only assigned on the first settings save, so a
// deployment configured entirely from the environment — the deployment this
// exists for — may never have acquired any. The index is the fallback, and is
// the identity the environment itself addresses elements by in
// `smtp.0.password`. Only when the caller has no UUID, so that a form whose
// blocks have been reordered cannot reach the wrong element merely because it
// also sent an index.
func ManagedElement(ko *koanf.Koanf, keys []string, section, uuid string, index int) (*koanf.Koanf, bool) {
	elements := ko.Slices(section)

	at := -1
	if uuid != "" {
		for i, element := range elements {
			if element.String("uuid") == uuid {
				at = i
				break
			}
		}
	} else if index >= 0 && index < len(elements) {
		at = index
	}

	if at < 0 {
		return nil, false
	}

	prefix := fmt.Sprintf("%s%s%d%s", section, Delim, at, Delim)
	for _, key := range keys {
		if strings.HasPrefix(key, prefix) {
			return elements[at], true
		}
	}

	return nil, false
}

// Effective overlays, onto a decoded settings document, the values ko holds for
// the given keys.
//
// The document is the settings JSON, whose top-level keys are themselves dotted
// ("app.root_url" is one key, not two levels), except for list sections like
// "smtp" which hold arrays and a few blocks — "security.oidc",
// "security.captcha" — which hold objects. Those three shapes are the only ones
// settings use.
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

		// A flat key `omitempty` elided because what is stored is empty. Absent
		// for that reason is not the same as absent because the settings
		// document does not carry the key at all, which is what the skip at the
		// bottom is for, and only an enumerated key can tell the two apart.
		if omitemptyKeys[key] {
			doc[key] = ko.String(key)
			continue
		}

		if m := indexedKeyRe.FindStringSubmatch(key); m != nil {
			applyIndexed(doc, ko, slices, m)
			continue
		}

		// A block key. `security.oidc` is ONE settings key whose value is an
		// object, so `security.oidc.enabled` is not in the document at any
		// level either branch above looks at.
		//
		// Without this, every OIDC and captcha value the environment supplied
		// was dropped on the floor and the form showed the database's stale
		// copy instead — a deployment whose OIDC was configured entirely from
		// the environment displayed as switched off.
		if block, field, ok := nestedField(doc, key); ok {
			block[field] = valueLike(block[field], ko, key)
			continue
		}

		// A key the settings document does not carry. Config-file-only settings
		// such as `app.address` and the whole `db` block live in the
		// environment and never in the database, so this is ordinary.
	}
}

// applyIndexed overlays a key naming one field of one element of a list
// section, e.g. `smtp.0.password`, from the submatch indexedKeyRe produced.
func applyIndexed(doc map[string]any, ko *koanf.Koanf, slices map[string][]*koanf.Koanf, m []string) {
	section, field := m[1], m[3]

	index, err := strconv.Atoi(m[2])
	if err != nil {
		return
	}

	list, ok := doc[section].([]any)
	if !ok || index >= len(list) {
		return
	}

	element, ok := list[index].(map[string]any)
	if !ok {
		return
	}

	if _, ok := slices[section]; !ok {
		slices[section] = ko.Slices(section)
	}

	running := slices[section]
	if index >= len(running) {
		return
	}

	existing, present := element[field]
	if !present {
		// Absent from the document rather than null in it. `omitempty` elides
		// an empty value, and every field it is set on in models.Settings is a
		// credential STRING — smtp, messengers and bounce.mailboxes all tag
		// their password that way — so a string is what belongs here.
		//
		// An empty stored password is the normal state for a deployment that
		// supplies it from the environment, which made this the common path
		// rather than an edge: inferring a type for it instead put a number
		// where the struct has a string whenever the password was all digits,
		// and one failed decode discards the whole overlay.
		element[field] = running[index].String(field)
		return
	}

	element[field] = valueLike(existing, running[index], field)
}

// nestedField resolves key against the document's object blocks, returning the
// map that directly holds the key's last segment, and that segment.
//
// The longest top-level key that prefixes the environment key names the block,
// and what remains addresses a field within it. Longest first, so that a
// document carrying both "security" and "security.oidc" resolves to the more
// specific one; and a block may nest again, as "security.captcha" does into
// "altcha" and "hcaptcha".
func nestedField(doc map[string]any, key string) (map[string]any, string, bool) {
	for cut := strings.LastIndex(key, Delim); cut > 0; cut = strings.LastIndex(key[:cut], Delim) {
		block, ok := doc[key[:cut]].(map[string]any)
		if !ok {
			continue
		}

		path := strings.Split(key[cut+len(Delim):], Delim)
		for _, segment := range path[:len(path)-1] {
			next, ok := block[segment].(map[string]any)
			if !ok {
				return nil, "", false
			}

			block = next
		}

		field := path[len(path)-1]
		if _, ok := block[field]; !ok {
			// The document is marshalled from the settings struct, so every
			// field it has is present. One that is not is a key the struct does
			// not declare — a typo, or a config-file-only setting that happens
			// to sit under a block — and inventing it would only fail the
			// decode that puts the document back.
			return nil, "", false
		}

		return block, field, true
	}

	return nil, "", false
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
	case nil:
		// A setting that is null when unset, which is how the `null.Int` roles
		// under security.oidc marshal. Leaving the environment's string in
		// place of one would fail the decode and discard the whole overlay, so
		// the type has to be guessed — see infer.
		return infer(ko.String(key))
	default:
		// A nested object. Nothing delivers one of those whole by environment
		// today, and Effective's caller treats a document it cannot decode as a
		// reason to show the stored settings instead.
		return ko.Get(key)
	}
}

// infer reads a value whose intended type the settings document does not state,
// because what it holds there is null.
//
// JSON's own spelling is the best guide available, and the case this exists for
// is narrow: security.oidc.default_user_role_id and its list counterpart are
// `null.Int`, they are exactly what an OIDC-only deployment sets from the
// environment, and they decode from a number but not from "2".
func infer(raw string) any {
	if raw == "" {
		return nil
	}

	// Before ParseBool, which would take "1" and "0" as booleans.
	if n, err := strconv.ParseFloat(raw, 64); err == nil {
		return n
	}

	if b, err := strconv.ParseBool(raw); err == nil {
		return b
	}

	return raw
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
