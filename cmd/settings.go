package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/gdgvda/cron"
	"github.com/gofrs/uuid/v5"
	"github.com/jmoiron/sqlx/types"
	koanfjson "github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"
	"github.com/knadh/listmonk/internal/auth"
	"github.com/knadh/listmonk/internal/envcfg"
	"github.com/knadh/listmonk/internal/messenger/email"
	"github.com/knadh/listmonk/internal/notifs"
	"github.com/knadh/listmonk/internal/secrets"
	"github.com/knadh/listmonk/models"
	"github.com/labstack/echo/v4"
)

const pwdMask = "•"

type aboutHost struct {
	OS       string `json:"os"`
	Machine  string `json:"arch"`
	Hostname string `json:"hostname"`
}

type aboutSystem struct {
	NumCPU  int    `json:"num_cpu"`
	AllocMB uint64 `json:"memory_alloc_mb"`
	OSMB    uint64 `json:"memory_from_os_mb"`
}

type about struct {
	Version   string         `json:"version"`
	Build     string         `json:"build"`
	GoVersion string         `json:"go_version"`
	GoArch    string         `json:"go_arch"`
	Database  types.JSONText `json:"database"`
	System    aboutSystem    `json:"system"`
	Host      aboutHost      `json:"host"`
}

var (
	reAlphaNum = regexp.MustCompile(`[^a-z0-9\-]`)
)

// The key the settings document carries its environment-managed key list under.
// Dotted like every other settings key, and absent from models.Settings, so a
// form that posts it straight back is ignored rather than rejected.
const envManagedKey = "env.managed_keys"

// GetSettings returns settings from the DB.
func (a *App) GetSettings(c echo.Context) error {
	s, err := a.core.GetSettings()
	if err != nil {
		return err
	}

	// What the environment supplies, so the form can show what is RUNNING
	// rather than what is stored. These are read from the database, but the
	// environment was put back on top of them at load, so without this the form
	// shows values the app is not using and invites edits that silently revert.
	envKeys, err := a.effectiveSettings(&s)
	if err != nil {
		return err
	}

	// Empty out passwords.
	for i := range s.SMTP {
		s.SMTP[i].Password = strings.Repeat(pwdMask, utf8.RuneCountInString(s.SMTP[i].Password))
	}
	for i := range s.BounceBoxes {
		s.BounceBoxes[i].Password = strings.Repeat(pwdMask, utf8.RuneCountInString(s.BounceBoxes[i].Password))
	}
	for i := range s.Messengers {
		s.Messengers[i].Password = strings.Repeat(pwdMask, utf8.RuneCountInString(s.Messengers[i].Password))
	}

	s.UploadS3AwsSecretAccessKey = strings.Repeat(pwdMask, utf8.RuneCountInString(s.UploadS3AwsSecretAccessKey))
	s.SendgridKey = strings.Repeat(pwdMask, utf8.RuneCountInString(s.SendgridKey))
	s.BounceAzure.SharedSecret = strings.Repeat(pwdMask, utf8.RuneCountInString(s.BounceAzure.SharedSecret))
	s.BouncePostmark.Password = strings.Repeat(pwdMask, utf8.RuneCountInString(s.BouncePostmark.Password))
	s.BounceForwardEmail.Key = strings.Repeat(pwdMask, utf8.RuneCountInString(s.BounceForwardEmail.Key))
	s.BounceLettermint.Key = strings.Repeat(pwdMask, utf8.RuneCountInString(s.BounceLettermint.Key))
	s.SecurityCaptcha.HCaptcha.Secret = strings.Repeat(pwdMask, utf8.RuneCountInString(s.SecurityCaptcha.HCaptcha.Secret))
	s.OIDC.ClientSecret = strings.Repeat(pwdMask, utf8.RuneCountInString(s.OIDC.ClientSecret))

	// Masked AFTER the overlay, so an env-supplied credential is shown the same
	// way a stored one is. What the operator needs from those fields is not the
	// value but the knowledge that editing them here does nothing, which is what
	// the key list below is for.
	out, err := settingsWithEnvKeys(s, envKeys)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, okResp{out})
}

// effectiveSettings overlays the running configuration onto s for every key the
// environment supplies, and returns those keys.
//
// Returns nothing at all when the operator has not asked for the environment to
// be authoritative, because then the database genuinely is the truth and the
// form is already showing it.
func (a *App) effectiveSettings(s *models.Settings) ([]string, error) {
	if !ko.Bool("app.env_overrides_settings") {
		return nil, nil
	}

	keys, err := envcfg.Keys()
	if err != nil {
		a.log.Printf("error reading env keys: %v", err)
		return nil, echo.NewHTTPError(http.StatusInternalServerError, a.i18n.Ts("globals.messages.internalError"))
	}

	// Round-tripped through JSON because the settings document is addressed by
	// the same dotted paths the environment uses, and its json tags are the only
	// place that mapping exists.
	doc := map[string]any{}
	if err := remarshal(s, &doc); err != nil {
		a.log.Printf("error decoding settings: %v", err)
		return nil, echo.NewHTTPError(http.StatusInternalServerError, a.i18n.Ts("globals.messages.internalError"))
	}

	envcfg.Effective(doc, ko, keys)

	// Decoded into a fresh value and only then assigned, so that a key whose
	// environment form does not fit the settings type degrades to showing the
	// stored values rather than failing the whole page or leaving s half
	// written. Every environment value is a string and the overlay converts them
	// by the type already in the document, which cannot cover a shape nothing
	// delivers by environment yet.
	var overlaid models.Settings
	if err := remarshal(doc, &overlaid); err != nil {
		a.log.Printf("error applying env over settings, showing stored values: %v", err)
		return keys, nil
	}

	*s = overlaid

	return keys, nil
}

// settingsWithEnvKeys renders settings as the document the UI consumes, with the
// environment-managed keys named under a key of its own.
//
// A sibling key rather than a wrapper object: the admin UI reads settings as a
// flat map addressed by dotted path, and every other shape would mean changing
// each of its nine tabs.
func settingsWithEnvKeys(s models.Settings, keys []string) (map[string]any, error) {
	doc := map[string]any{}
	if err := remarshal(s, &doc); err != nil {
		return nil, err
	}

	// Always present, so the UI can rely on it rather than testing for it.
	if keys == nil {
		keys = []string{}
	}

	doc[envManagedKey] = keys

	return doc, nil
}

// remarshal converts between shapes that share their JSON representation.
func remarshal(from any, to any) error {
	b, err := json.Marshal(from)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, to)
}

// UpdateSettings returns settings from the DB.
func (a *App) UpdateSettings(c echo.Context) error {
	// Unmarshal and marshal the fields once to sanitize the settings blob.
	var set models.Settings
	if err := c.Bind(&set); err != nil {
		return err
	}

	// Get the existing settings.
	cur, err := a.core.GetSettings()
	if err != nil {
		return err
	}

	// Validate and sanitize postback Messenger names along with SMTP names
	// (where each SMTP is also considered as a standalone messenger).
	// Duplicates are disallowed and "email" is a reserved name.
	names := map[string]bool{emailMsgr: true}

	// There should be at least one SMTP block that's enabled.
	has := false
	for i, s := range set.SMTP {
		if s.Enabled {
			has = true
		}

		// Sanitize and normalize the SMTP server name.
		name := reAlphaNum.ReplaceAllString(strings.ToLower(strings.TrimSpace(s.Name)), "-")
		if name != "" {
			if !strings.HasPrefix(name, "email-") {
				name = "email-" + name
			}

			if _, ok := names[name]; ok {
				return echo.NewHTTPError(http.StatusBadRequest,
					a.i18n.Ts("settings.duplicateMessengerName", "name", name))
			}

			names[name] = true
		}
		set.SMTP[i].Name = name

		// Assign a UUID. The frontend only sends a password when the user explicitly
		// changes the password. In other cases, the existing password in the DB
		// is copied while updating the settings and the UUID is used to match
		// the incoming array of SMTP blocks with the array in the DB.
		if s.UUID == "" {
			set.SMTP[i].UUID = uuid.Must(uuid.NewV4()).String()
		}

		// Ensure the HOST is trimmed of any whitespace.
		// This is a common mistake when copy-pasting SMTP settings.
		set.SMTP[i].Host = strings.TrimSpace(s.Host)

		// If there's no password coming in from the frontend, copy the existing
		// password by matching the UUID.
		if s.Password == "" {
			for _, c := range cur.SMTP {
				if s.UUID == c.UUID {
					set.SMTP[i].Password = c.Password
				}
			}
		}
	}
	if !has {
		return echo.NewHTTPError(http.StatusBadRequest, a.i18n.T("settings.errorNoSMTP"))
	}

	// Normalize `from_addresses``. Values are either an e-mail address
	// or an FQDN. Duplicate domains across server blocks are allowed
	// (they get round-robin'd while sending).
	for i, s := range set.SMTP {
		if !s.Enabled {
			continue
		}

		addrs := make([]string, 0, len(s.FromAddresses))
		for _, addr := range s.FromAddresses {
			if k := email.NormalizeAddr(addr); k != "" {
				addrs = append(addrs, k)
			}
		}
		set.SMTP[i].FromAddresses = addrs
	}

	// Always remove the trailing slash from the app root URL.
	set.AppRootURL = strings.TrimRight(set.AppRootURL, "/")

	// Bounce boxes.
	for i, s := range set.BounceBoxes {
		// Assign a UUID. The frontend only sends a password when the user explicitly
		// changes the password. In other cases, the existing password in the DB
		// is copied while updating the settings and the UUID is used to match
		// the incoming array of blocks with the array in the DB.
		if s.UUID == "" {
			set.BounceBoxes[i].UUID = uuid.Must(uuid.NewV4()).String()
		}

		// Ensure the HOST is trimmed of any whitespace.
		// This is a common mistake when copy-pasting SMTP settings.
		set.BounceBoxes[i].Host = strings.TrimSpace(s.Host)

		if d, _ := time.ParseDuration(s.ScanInterval); d.Minutes() < 1 {
			return echo.NewHTTPError(http.StatusBadRequest, a.i18n.T("settings.bounces.invalidScanInterval"))
		}

		// If there's no password coming in from the frontend, copy the existing
		// password by matching the UUID.
		if s.Password == "" {
			for _, c := range cur.BounceBoxes {
				if s.UUID == c.UUID {
					set.BounceBoxes[i].Password = c.Password
				}
			}
		}
	}

	for i, m := range set.Messengers {
		// UUID to keep track of password changes similar to the SMTP logic above.
		if m.UUID == "" {
			set.Messengers[i].UUID = uuid.Must(uuid.NewV4()).String()
		}

		if m.Password == "" {
			for _, c := range cur.Messengers {
				if m.UUID == c.UUID {
					set.Messengers[i].Password = c.Password
				}
			}
		}

		name := reAlphaNum.ReplaceAllString(strings.ToLower(m.Name), "")
		if _, ok := names[name]; ok {
			return echo.NewHTTPError(http.StatusBadRequest,
				a.i18n.Ts("settings.duplicateMessengerName", "name", name))
		}
		if len(name) == 0 {
			return echo.NewHTTPError(http.StatusBadRequest, a.i18n.T("settings.invalidMessengerName"))
		}

		set.Messengers[i].Name = name
		names[name] = true
	}

	// S3 password?
	if set.UploadS3AwsSecretAccessKey == "" {
		set.UploadS3AwsSecretAccessKey = cur.UploadS3AwsSecretAccessKey
	}
	if set.SendgridKey == "" {
		set.SendgridKey = cur.SendgridKey
	}
	if set.BounceAzure.SharedSecret == "" {
		set.BounceAzure.SharedSecret = cur.BounceAzure.SharedSecret
	}
	if set.BouncePostmark.Password == "" {
		set.BouncePostmark.Password = cur.BouncePostmark.Password
	}
	if set.BounceForwardEmail.Key == "" {
		set.BounceForwardEmail.Key = cur.BounceForwardEmail.Key
	}
	if set.BounceLettermint.Key == "" {
		set.BounceLettermint.Key = cur.BounceLettermint.Key
	}
	if set.SecurityCaptcha.HCaptcha.Secret == "" {
		set.SecurityCaptcha.HCaptcha.Secret = cur.SecurityCaptcha.HCaptcha.Secret
	}
	// Secret references are validated BEFORE the write. The value is only
	// parsed in the process that respawns after this save, and a failure there
	// is fatal — so a typo'd reference would take the instance down with the
	// admin UI gone, leaving SQL as the only way to undo it. This is syntax
	// only: no network call, no vault contact.
	for i, s := range set.SMTP {
		if err := secrets.Validate(s.Password); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest,
				fmt.Sprintf("smtp[%d].password: %v", i, err))
		}
	}

	if err := secrets.Validate(set.OIDC.ClientSecret); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			fmt.Sprintf("security.oidc.client_secret: %v", err))
	}

	if set.OIDC.ClientSecret == "" {
		set.OIDC.ClientSecret = cur.OIDC.ClientSecret
	}

	// OIDC user auto-creation is enabled. Validate.
	if set.OIDC.AutoCreateUsers {
		if set.OIDC.DefaultUserRoleID.Int < auth.SuperAdminRoleID {
			return echo.NewHTTPError(http.StatusBadRequest,
				a.i18n.Ts("globals.messages.invalidFields", "name", a.i18n.T("settings.security.OIDCDefaultRole")))
		}
	}

	for n, v := range set.UploadExtensions {
		set.UploadExtensions[n] = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(v), "."))
	}

	// Domain blocklist / allowlist.
	doms := make([]string, 0, len(set.DomainBlocklist))
	for _, d := range set.DomainBlocklist {
		if d = strings.TrimSpace(strings.ToLower(d)); d != "" {
			doms = append(doms, d)
		}
	}
	set.DomainBlocklist = doms

	doms = make([]string, 0, len(set.DomainAllowlist))
	for _, d := range set.DomainAllowlist {
		if d = strings.TrimSpace(strings.ToLower(d)); d != "" {
			doms = append(doms, d)
		}
	}
	set.DomainAllowlist = doms

	// Validate and clean trusted URLs.
	urls := make([]string, 0, len(set.SecurityTrustedURLs))
	for _, d := range set.SecurityTrustedURLs {
		if d = strings.TrimSpace(d); d != "" {
			if d == "*" {
				urls = append(urls, d)
				continue
			}

			// Parse and validate the URL.
			u, err := url.Parse(d)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return echo.NewHTTPError(http.StatusBadRequest,
					a.i18n.Ts("globals.messages.invalidData")+": invalid trusted URL: "+d)
			}
			urls = append(urls, d)
		}
	}
	set.SecurityTrustedURLs = urls

	// Validate slow query caching cron.
	if set.CacheSlowQueries {
		if _, err := cron.ParseStandard(set.CacheSlowQueriesInterval); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, a.i18n.Ts("globals.messages.invalidData")+": slow query cron: "+err.Error())
		}
	}

	// Update the settings in the DB.
	if err := a.core.UpdateSettings(set); err != nil {
		return err
	}

	return a.handleSettingsRestart(c)
}

// UpdateSettingsByKey updates a single setting key-value in the DB.
func (a *App) UpdateSettingsByKey(c echo.Context) error {
	key := c.Param("key")
	if key == "" {
		return echo.NewHTTPError(http.StatusBadRequest, a.i18n.T("globals.messages.invalidData"))
	}

	// Read the raw JSON body as the value.
	var b json.RawMessage
	if err := c.Bind(&b); err != nil {
		return err
	}

	// Update the value in the DB.
	if err := a.core.UpdateSettingsByKey(key, b); err != nil {
		return err
	}

	return a.handleSettingsRestart(c)
}

// handleSettingsRestart checks for running campaigns and either triggers an
// immediate app restart or marks the app as needing a restart.
func (a *App) handleSettingsRestart(c echo.Context) error {
	// If there are any active campaigns, don't do an auto reload and
	// warn the user on the frontend.
	if a.manager.HasRunningCampaigns() {
		a.Lock()
		a.needsRestart = true
		a.Unlock()

		return c.JSON(http.StatusOK, okResp{struct {
			NeedsRestart bool `json:"needs_restart"`
		}{true}})
	}

	// No running campaigns. Reload the app.
	go func() {
		<-time.After(time.Millisecond * 500)
		a.chReload <- syscall.SIGHUP
	}()

	return c.JSON(http.StatusOK, okResp{true})
}

// GetLogs returns the log entries stored in the log buffer.
func (a *App) GetLogs(c echo.Context) error {
	return c.JSON(http.StatusOK, okResp{a.bufLog.Lines()})
}

// TestSMTPSettings returns the log entries stored in the log buffer.
func (a *App) TestSMTPSettings(c echo.Context) error {
	// Copy the raw JSON post body.
	reqBody, err := io.ReadAll(c.Request().Body)
	if err != nil {
		a.log.Printf("error reading SMTP test: %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, a.i18n.Ts("globals.messages.internalError"))
	}

	// Load the JSON into koanf to parse SMTP settings properly including timestrings.
	ko := koanf.New(".")
	if err := ko.Load(rawbytes.Provider(reqBody), koanfjson.Parser()); err != nil {
		a.log.Printf("error unmarshalling SMTP test request: %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, a.i18n.Ts("globals.messages.internalError"))
	}

	req := email.Server{}
	if err := ko.UnmarshalWithConf("", &req, koanf.UnmarshalConf{Tag: "json"}); err != nil {
		a.log.Printf("error scanning SMTP test request: %v", err)
		return echo.NewHTTPError(http.StatusBadRequest, a.i18n.Ts("globals.messages.internalError"))
	}

	to := ko.String("email")
	if to == "" {
		return echo.NewHTTPError(http.StatusBadRequest, a.i18n.Ts("globals.messages.missingFields", "name", "email"))
	}

	// If this server is managed by the environment, test what the app actually
	// sends with rather than what the form posted.
	//
	// Without this the button cannot test such a server at all: the form shows
	// the database row, which for an env-managed deployment is whatever the
	// installer left there, and the password field holds a mask. It would dial
	// some default host with an empty password and report a failure that says
	// nothing about the configured relay.
	//
	// DELIBERATELY NOT "resolve secret references in the request". That reads
	// like the same fix and is a credential exfiltration primitive: anyone with
	// settings:manage could post a reference to any secret this identity can
	// read, point host at a listener of their own, and collect the resolved
	// value from the AUTH exchange. Here the caller chooses neither the host nor
	// the password; both come from the running configuration.
	if live, ok := a.liveSMTPServer(ko.String("uuid")); ok {
		live.EmailHeaders = req.EmailHeaders
		req = live
	}

	// Initialize a new SMTP pool.
	req.MaxConns = 1
	req.IdleTimeout = time.Second * 2
	req.PoolWaitTimeout = time.Second * 2
	msgr, err := email.New("", req)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest,
			a.i18n.Ts("globals.messages.errorCreating", "name", "SMTP", "error", err.Error()))
	}

	// Render the test email template body.
	var b bytes.Buffer
	if err := notifs.Tpls.ExecuteTemplate(&b, "smtp-test", nil); err != nil {
		a.log.Printf("error compiling notification template '%s': %v", "smtp-test", err)
		return err
	}

	m := models.Message{}
	m.From = a.cfg.FromEmail
	m.To = []string{to}
	m.Subject = a.i18n.T("settings.smtp.testConnection")
	m.Body = b.Bytes()
	if err := msgr.Push(m); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, okResp{a.bufLog.Lines()})
}

func (a *App) GetAboutInfo(c echo.Context) error {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	out := a.about
	out.System.AllocMB = mem.Alloc / 1024 / 1024
	out.System.OSMB = mem.Sys / 1024 / 1024

	return c.JSON(http.StatusOK, out)
}

// liveSMTPServer returns the running configuration for the SMTP block with this
// UUID, when the environment is what supplies it.
//
// Matched by UUID rather than by position because the UUID is the only stable
// identity an SMTP block has: it is assigned once, stored in the database, and
// survives blocks being reordered or removed in the admin UI. The environment
// overrides fields within a block and never the UUID, so the block the form is
// testing and the block the app is running are the same row.
func (a *App) liveSMTPServer(uuid string) (email.Server, bool) {
	if uuid == "" || !ko.Bool("app.env_overrides_settings") {
		return email.Server{}, false
	}

	keys, err := envcfg.Keys()
	if err != nil {
		a.log.Printf("error reading env keys: %v", err)
		return email.Server{}, false
	}

	managed := false
	for _, key := range keys {
		if strings.HasPrefix(key, "smtp"+envcfg.Delim) {
			managed = true
			break
		}
	}

	if !managed {
		return email.Server{}, false
	}

	for _, block := range ko.Slices("smtp") {
		if block.String("uuid") != uuid {
			continue
		}

		var srv email.Server
		if err := block.UnmarshalWithConf("", &srv, koanf.UnmarshalConf{Tag: "json"}); err != nil {
			a.log.Printf("error reading live SMTP config: %v", err)
			return email.Server{}, false
		}

		// The password is a reference in exactly the deployment this exists for,
		// and resolving it is the app's own privilege rather than the caller's.
		srv.Password = resolveSecret(srv.Password)

		return srv, true
	}

	return email.Server{}, false
}
