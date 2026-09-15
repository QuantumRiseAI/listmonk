<template>
  <form @submit.prevent="onSubmit">
    <section class="settings">
      <b-loading :is-full-page="true" v-if="loading.settings || isLoading" active />
      <header class="columns page-header">
        <div class="column is-half">
          <h1 class="title is-4">
            {{ $t('settings.title') }}
            <span class="has-text-grey-light">({{ serverConfig.version }})</span>
          </h1>
        </div>
        <div class="column has-text-right">
          <b-field v-if="$can('settings:manage')" expanded>
            <b-button expanded :disabled="!hasFormChanged" type="is-primary" icon-left="content-save-outline"
              native-type="submit" class="isSaveEnabled" data-cy="btn-save">
              {{ $t('globals.buttons.save') }}
            </b-button>
          </b-field>
        </div>
      </header>
      <hr />

      <section class="wrap settings-wrap" v-if="form">
        <b-tabs class="settings-tabs" vertical :animated="false" v-model="tab">
          <b-tab-item :label="$t('settings.general.name')">
            <general-settings :form="form" :key="key" />
          </b-tab-item><!-- general -->

          <b-tab-item :label="$t('settings.performance.name')">
            <performance-settings :form="form" :key="key" />
          </b-tab-item><!-- performance -->

          <b-tab-item :label="$t('settings.privacy.name')">
            <privacy-settings :form="form" :key="key" />
          </b-tab-item><!-- privacy -->

          <b-tab-item :label="$t('settings.security.name')">
            <security-settings :form="form" :key="key" />
          </b-tab-item><!-- security -->

          <b-tab-item :label="$t('settings.media.title')">
            <media-settings :form="form" :key="key" />
          </b-tab-item><!-- media -->

          <b-tab-item :label="$t('settings.smtp.name')">
            <smtp-settings ref="smtpTab" :form="form" :env-managed-keys="envManagedKeys" :key="key" />
          </b-tab-item><!-- mail servers -->

          <b-tab-item :label="$t('settings.bounces.name')">
            <bounce-settings ref="bouncesTab" :form="form" :key="key" />
          </b-tab-item><!-- bounces -->

          <b-tab-item :label="$t('settings.messengers.name')">
            <messenger-settings ref="messengersTab" :form="form" :key="key" />
          </b-tab-item><!-- messengers -->

          <b-tab-item :label="$t('settings.appearance.name')">
            <appearance-settings :form="form" :key="key" />
          </b-tab-item><!-- appearance -->
        </b-tabs>
      </section>
    </section>
  </form>
</template>

<script>
import Vue from 'vue';
import { mapState } from 'vuex';
import AppearanceSettings from './settings/appearance.vue';
import BounceSettings from './settings/bounces.vue';
import GeneralSettings from './settings/general.vue';
import MediaSettings from './settings/media.vue';
import MessengerSettings from './settings/messengers.vue';
import PerformanceSettings from './settings/performance.vue';
import PrivacySettings from './settings/privacy.vue';
import SecuritySettings from './settings/security.vue';
import SmtpSettings from './settings/smtp.vue';

// Input names for settings keys whose field is not named after the key.
//
// Every tab but security names its inputs for the settings key, which is what
// lockEnvManagedFields matches on. Security names them for the field —
// `oidc.client_id` rather than `security.oidc.client_id` — so without this
// table the whole OIDC block stays editable however the environment sets it.
//
// Mapped here rather than renamed there, to keep the fork's diff out of a file
// upstream still edits.
const FIELD_NAMES = {
  'security.oidc.enabled': ['security.oidc'],
  'security.oidc.provider_url': ['oidc.provider_url'],
  'security.oidc.provider_name': ['oidc.provider_name'],
  'security.oidc.client_id': ['oidc.client_id'],
  'security.oidc.client_secret': ['oidc.client_secret'],
  'security.oidc.auto_create_users': ['oidc.auto_create_users'],
  'security.oidc.default_user_role_id': ['oidc.default_user_role_id'],
  'security.oidc.default_list_role_id': ['oidc.default_list_role_id'],

  // The master switch is a computed proxy over both providers' `enabled`, and
  // the radios choose between them, so either flag being env-set makes both
  // controls futile.
  'security.captcha.altcha.enabled': ['security.captcha', 'captcha_provider'],
  'security.captcha.hcaptcha.enabled': ['security.captcha', 'captcha_provider'],
  'security.captcha.altcha.complexity': ['altcha_complexity'],
  'security.captcha.hcaptcha.key': ['hcaptcha_key'],
  'security.captcha.hcaptcha.secret': ['hcaptcha_secret'],

  'security.trusted_urls': ['trusted_urls'],
};

// Settings sections that hold a list, and the ref of the tab component that
// renders one. All three are addressed by the environment as `<section>.N.field`
// and all three are overlaid by the backend, so all three have to lock.
const LIST_SECTIONS = {
  smtp: 'smtpTab',
  'bounce.mailboxes': 'bouncesTab',
  messengers: 'messengersTab',
};

export default Vue.extend({
  components: {
    GeneralSettings,
    PerformanceSettings,
    PrivacySettings,
    SecuritySettings,
    MediaSettings,
    SmtpSettings,
    BounceSettings,
    MessengerSettings,
    AppearanceSettings,
  },

  data() {
    return {
      // :key="key" is a ack to re-render child components every time settings
      // is pulled. Otherwise, props don't react.
      key: 0,

      isLoading: false,

      // formCopy is a stringified copy of the original settings against which
      // form is compared to detect changes.
      formCopy: '',
      form: null,
      tab: 0,

      // Settings keys the environment supplies. Their inputs are disabled:
      // the values shown are what the app is running, and an edit would be
      // silently reverted on the next start.
      envManagedKeys: [],
    };
  },

  methods: {
    async onSubmit() {
      const form = JSON.parse(JSON.stringify(this.form));

      // SMTP boxes.
      let hasDummy = '';
      for (let i = 0; i < form.smtp.length; i += 1) {
        // trim the host before saving
        form.smtp[i].host = form.smtp[i].host?.trim();

        // If it's the dummy UI password placeholder, ignore it.
        if (this.isDummy(form.smtp[i].password)) {
          form.smtp[i].password = '';
        } else if (this.hasDummy(form.smtp[i].password)) {
          hasDummy = `smtp #${i + 1}`;
        }

        if (form.smtp[i].strEmailHeaders && form.smtp[i].strEmailHeaders !== '[]') {
          form.smtp[i].email_headers = JSON.parse(form.smtp[i].strEmailHeaders);
        } else {
          form.smtp[i].email_headers = [];
        }
      }

      // Bounces boxes.
      for (let i = 0; i < form['bounce.mailboxes'].length; i += 1) {
        // trim the host before saving
        form['bounce.mailboxes'][i].host = form['bounce.mailboxes'][i].host?.trim();

        // If it's the dummy UI password placeholder, ignore it.
        if (this.isDummy(form['bounce.mailboxes'][i].password)) {
          form['bounce.mailboxes'][i].password = '';
        } else if (this.hasDummy(form['bounce.mailboxes'][i].password)) {
          hasDummy = `bounce #${i + 1}`;
        }
      }

      if (this.isDummy(form['upload.s3.aws_secret_access_key'])) {
        form['upload.s3.aws_secret_access_key'] = '';
      } else if (this.hasDummy(form['upload.s3.aws_secret_access_key'])) {
        hasDummy = 's3';
      }

      if (this.isDummy(form['bounce.sendgrid_key'])) {
        form['bounce.sendgrid_key'] = '';
      } else if (this.hasDummy(form['bounce.sendgrid_key'])) {
        hasDummy = 'sendgrid';
      }

      if (this.isDummy(form['bounce.azure'].shared_secret)) {
        form['bounce.azure'].shared_secret = '';
      } else if (this.hasDummy(form['bounce.azure'].shared_secret)) {
        hasDummy = 'azure shared secret';
      }

      if (this.isDummy(form['security.captcha'].hcaptcha.secret)) {
        form['security.captcha'].hcaptcha.secret = '';
      } else if (this.hasDummy(form['security.captcha'].hcaptcha.secret)) {
        hasDummy = 'captcha';
      }

      if (this.isDummy(form['security.oidc'].client_secret)) {
        form['security.oidc'].client_secret = '';
      } else if (this.hasDummy(form['security.oidc'].client_secret)) {
        hasDummy = 'oidc';
      }

      if (this.isDummy(form['bounce.postmark'].password)) {
        form['bounce.postmark'].password = '';
      } else if (this.hasDummy(form['bounce.postmark'].password)) {
        hasDummy = 'postmark';
      }

      if (this.isDummy(form['bounce.forwardemail'].key)) {
        form['bounce.forwardemail'].key = '';
      } else if (this.hasDummy(form['bounce.forwardemail'].key)) {
        hasDummy = 'forwardemail';
      }

      if (this.isDummy(form['bounce.lettermint'].key)) {
        form['bounce.lettermint'].key = '';
      } else if (this.hasDummy(form['bounce.lettermint'].key)) {
        hasDummy = 'lettermint';
      }

      for (let i = 0; i < form.messengers.length; i += 1) {
        // If it's the dummy UI password placeholder, ignore it.
        if (this.isDummy(form.messengers[i].password)) {
          form.messengers[i].password = '';
        } else if (this.hasDummy(form.messengers[i].password)) {
          hasDummy = `messenger #${i + 1}`;
        }
      }

      if (hasDummy) {
        this.$utils.toast(this.$t('globals.messages.passwordChangeFull', { name: hasDummy }), 'is-danger');
        return false;
      }

      // Domain blocklist array from multi-line strings.
      form['privacy.domain_blocklist'] = form['privacy.domain_blocklist'].split('\n').map((v) => v.trim().toLowerCase()).filter((v) => v !== '');
      form['privacy.domain_allowlist'] = form['privacy.domain_allowlist'].split('\n').map((v) => v.trim().toLowerCase()).filter((v) => v !== '');

      this.isLoading = true;
      try {
        const data = await this.$api.updateSettings(form);
        await this.$root.awaitRestart(data);
        this.getSettings();
      } finally {
        this.isLoading = false;
      }

      return false;
    },

    // Undo lockEnvManagedFields, so that a re-render cannot leave a disabled
    // input sitting against a block it was not disabled for.
    unlockEnvManagedFields() {
      if (!this.$el.querySelectorAll) {
        return;
      }

      this.$el.querySelectorAll('.env-managed').forEach((el) => {
        el.removeAttribute('disabled');
        el.removeAttribute('title');
        el.classList.remove('env-managed');
      });
    },

    // Keep the locks applied across re-renders.
    //
    // The attribute is set outside Vue, and on several of these inputs Vue owns
    // it: smtp.vue binds :disabled="item.auth_protocol === 'none'" on username
    // and password, so changing the auth protocol makes Vue REMOVE the
    // attribute, taking the lock with it. Others sit behind v-if — security.vue
    // mounts the hcaptcha key and secret only for that provider, and the whole
    // captcha block only when enabled — so toggling either renders fresh,
    // unlocked inputs. Neither the tab watcher nor the SMTP-count watcher fires
    // for any of that, and the field went on showing "set by the environment"
    // while being perfectly editable.
    observeRerenders() {
      // Only worth running at all when something is env-managed, which for most
      // deployments is never — so this costs them nothing.
      if (this.lockObserver || !this.envManagedKeys.length) {
        return;
      }

      if (!window.MutationObserver || !this.$el || !this.$el.querySelectorAll) {
        return;
      }

      this.lockObserver = new MutationObserver(() => {
        this.$nextTick(() => this.lockEnvManagedFields());
      });

      this.startObserving();
    },

    startObserving() {
      if (this.lockObserver) {
        // `disabled` only: every other attribute change is Vue's business, and
        // watching them all would rerun this on every keystroke.
        this.lockObserver.observe(this.$el, {
          childList: true, subtree: true, attributes: true, attributeFilter: ['disabled'],
        });
      }
    },

    stopObserving() {
      if (this.lockObserver) {
        this.lockObserver.disconnect();
      }
    },

    // Disable the inputs for settings the environment supplies.
    //
    // Done against the rendered DOM rather than by passing a prop into each of
    // the nine tab components and binding :disabled on every field in them.
    // Every input already carries name="<settings key>", which is the mapping
    // this needs, and the alternative is an edit to every field in the form for
    // a case most deployments never hit.
    //
    // This is advisory, not a boundary: the form posts this.form rather than
    // the DOM, so a disabled input is no guarantee. What makes an env-managed
    // value safe is the server putting the stored one back on write.
    lockEnvManagedFields() {
      if (!this.envManagedKeys.length || !this.$el.querySelectorAll) {
        return;
      }

      // Our own attribute writes would otherwise re-enter through the observer.
      this.stopObserving();

      const plain = new Set();
      const lists = {};

      this.envManagedKeys.forEach((key) => {
        // `smtp.0.password` names one field of one block in a list section, and
        // `bounce.mailboxes.0.password` does the same for a DOTTED section.
        // Matched non-greedily, and allowing dots in the section, so that this
        // agrees with envcfg's own indexedKeyRe: requiring a dotless section
        // meant every bounce.mailboxes key fell through to the plain set,
        // matched no input, and locked nothing at all.
        const m = key.match(/^(.+?)\.(\d+)\.(.+)$/);
        if (!m) {
          (FIELD_NAMES[key] || [key]).forEach((name) => plain.add(name));
          return;
        }

        const [, section, index, field] = m;
        lists[section] = lists[section] || {};
        lists[section][index] = lists[section][index] || new Set();
        lists[section][index].add(field);
      });

      const disable = (el) => {
        if (!el) {
          return;
        }
        el.setAttribute('disabled', 'disabled');
        el.setAttribute('title', this.$t('settings.envManaged'));
        el.classList.add('env-managed');
      };

      this.$el.querySelectorAll('[name]').forEach((el) => {
        if (plain.has(el.getAttribute('name'))) {
          disable(el);
        }
      });

      // All three list sections, scoped through the tab component that renders
      // each. Scoped by ref rather than by a container class because bounce
      // mailboxes have no wrapping element of their own, and each of these
      // components renders exactly one `.block.box` — the v-for'd element —
      // so within a component the index is unambiguous.
      Object.entries(lists).forEach(([section, blocks]) => {
        const root = this.$refs[LIST_SECTIONS[section]];
        if (!root) {
          return;
        }

        const elements = root.$el.querySelectorAll('.block.box');

        Object.entries(blocks).forEach(([index, fields]) => {
          const block = elements[index];
          if (!block) {
            return;
          }

          block.querySelectorAll('[name]').forEach((el) => {
            if (fields.has(el.getAttribute('name'))) {
              disable(el);
            }
          });
        });
      });

      this.startObserving();
    },

    getSettings() {
      this.isLoading = true;
      this.$api.getSettings().then((data) => {
        let d = {};
        try {
          // Create a deep-copy of the settings hierarchy.
          d = JSON.parse(JSON.stringify(data));
        } catch (err) {
          return;
        }

        // Serialize the `email_headers` array map to display on the form.
        for (let i = 0; i < d.smtp.length; i += 1) {
          d.smtp[i].strEmailHeaders = JSON.stringify(d.smtp[i].email_headers, null, 4);
        }

        // Keys the environment manages. Taken out of the form so it is neither
        // posted back nor counted as a change against formCopy.
        this.envManagedKeys = d['env.managed_keys'] || [];
        delete d['env.managed_keys'];

        // Domain blocklist array to multi-line string.
        d['privacy.domain_blocklist'] = d['privacy.domain_blocklist'].join('\n');
        d['privacy.domain_allowlist'] = d['privacy.domain_allowlist'].join('\n');

        this.key += 1;
        this.form = d;
        this.formCopy = JSON.stringify(d);

        this.$nextTick(() => {
          // Unlocked first: a re-fetch re-renders the tabs, and a stale lock
          // left from the previous document could sit against a different block.
          this.unlockEnvManagedFields();
          this.lockEnvManagedFields();

          // Started here rather than in mounted, because only now is it known
          // whether anything is env-managed at all.
          this.observeRerenders();

          this.isLoading = false;
        });
      });
    },

    isDummy(pwd) {
      return !pwd || (pwd.match(/•/g) || []).length === pwd.length;
    },

    hasDummy(pwd) {
      return pwd.includes('•');
    },
  },

  computed: {
    ...mapState(['serverConfig', 'loading']),

    hasFormChanged() {
      if (!this.formCopy) {
        return false;
      }
      return JSON.stringify(this.form) !== this.formCopy;
    },
  },

  beforeRouteLeave(to, from, next) {
    if (this.hasFormChanged) {
      this.$utils.confirm(this.$t('globals.messages.confirmDiscard'), () => next(true));
      return;
    }
    next(true);
  },

  mounted() {
    this.tab = this.$utils.getPref('settings.tab') || 0;
    this.getSettings();
  },

  beforeDestroy() {
    this.stopObserving();
  },

  watch: {
    tab(t) {
      this.$utils.setPref('settings.tab', t);

      // Tab panels render lazily, so fields on a tab that has never been opened
      // do not exist to be disabled until now.
      this.$nextTick(() => {
        this.lockEnvManagedFields();
      });
    },

    // Adding or removing an SMTP block renders the list again, and its v-for is
    // keyed by index, so Vue reuses the DOM of block n for whatever block now
    // sits at n. A `disabled` set outside Vue survives that reuse and would end
    // up against the wrong server.
    'form.smtp.length': function smtpBlockCount() {
      this.$nextTick(() => {
        this.unlockEnvManagedFields();
        this.lockEnvManagedFields();
      });
    },
  },
});
</script>
