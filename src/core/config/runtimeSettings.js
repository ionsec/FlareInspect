/**
 * @fileoverview Runtime settings store.
 * @description A small, persistent settings overlay for the web dashboard so
 *   operators can configure notifications, the AI planner, and SIEM credentials
 *   from the UI without editing `.env` and restarting. Values are persisted to
 *   a local, git-ignored JSON file (`web/data/settings.json`, mode 0600).
 *
 *   Resolution precedence for every key: settings-file value (if a non-empty
 *   value was saved) → environment variable → null. The UI is therefore an
 *   *overlay* on top of `.env`, never a replacement — env stays authoritative
 *   when the UI hasn't set anything.
 *
 *   Secrets are write-only over the API: {@link maskedView} never returns a raw
 *   secret, only whether it is configured, where it came from, and a short hint.
 *
 *   The remediation kill-switch (FLAREINSPECT_ALLOW_REMEDIATION) and the MCP
 *   edit-scope token are intentionally NOT managed here — they stay env-only so
 *   the dashboard can never enable live Cloudflare writes from the browser.
 * @module core/config/runtimeSettings
 */

'use strict';

const fs = require('fs');
const path = require('path');

// key -> { env: <ENV VAR>, secret: <bool>, enum?: [allowed values] }
const KEYS = {
  // Notifications
  slackWebhook:    { env: 'FLAREINSPECT_SLACK_WEBHOOK',   secret: true },
  teamsWebhook:    { env: 'FLAREINSPECT_TEAMS_WEBHOOK',   secret: true },
  webhookUrl:      { env: 'FLAREINSPECT_WEBHOOK_URL',     secret: true },
  webhookSecret:   { env: 'FLAREINSPECT_WEBHOOK_SECRET',  secret: true },
  notifyThreshold: { env: 'FLAREINSPECT_NOTIFY_THRESHOLD', secret: false, enum: ['', 'critical', 'high', 'medium', 'low', 'informational'] },
  // AI planner
  aiProvider:      { env: 'FLAREINSPECT_AI_PROVIDER', secret: false, enum: ['', 'none', 'anthropic', 'openai', 'ollama'] },
  aiModel:         { env: 'FLAREINSPECT_AI_MODEL',    secret: false },
  anthropicApiKey: { env: 'ANTHROPIC_API_KEY',        secret: true },
  openaiApiKey:    { env: 'OPENAI_API_KEY',           secret: true },
  ollamaHost:      { env: 'OLLAMA_HOST',              secret: false },
  // SIEM
  esUrl:           { env: 'FLAREINSPECT_ES_URL',          secret: false },
  esApiKey:        { env: 'FLAREINSPECT_ES_APIKEY',       secret: true },
  esUsername:      { env: 'FLAREINSPECT_ES_USERNAME',     secret: false },
  esPassword:      { env: 'FLAREINSPECT_ES_PASSWORD',     secret: true },
  hecUrl:          { env: 'FLAREINSPECT_SPLUNK_HEC_URL',  secret: false },
  hecToken:        { env: 'FLAREINSPECT_SPLUNK_HEC_TOKEN', secret: true }
};

const DEFAULT_FILE = path.join(__dirname, '..', '..', '..', 'web', 'data', 'settings.json');

function filePath(opts = {}) {
  return opts.file || process.env.FLAREINSPECT_SETTINGS_FILE || DEFAULT_FILE;
}

/**
 * Load the raw saved settings object. Returns {} when the file is absent or
 * unreadable — settings are an optional overlay, never required.
 */
function loadSettings(opts = {}) {
  try {
    const raw = fs.readFileSync(filePath(opts), 'utf8');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (_) {
    return {};
  }
}

/**
 * Merge a partial settings patch and persist it (mode 0600).
 * - Unknown keys are ignored (the catalog is authoritative).
 * - An empty string clears a key (falls back to env again).
 * - `enum`-constrained keys reject invalid values.
 * @returns {object} the merged raw settings (secrets included — caller decides exposure)
 */
function saveSettings(patch = {}, opts = {}) {
  if (!patch || typeof patch !== 'object') {
    throw new Error('Settings payload must be an object.');
  }
  const current = loadSettings(opts);
  for (const [key, rawValue] of Object.entries(patch)) {
    const spec = KEYS[key];
    if (!spec) continue; // ignore unknown keys
    if (rawValue === null || rawValue === undefined) continue;
    const value = String(rawValue).trim();
    if (value === '') { delete current[key]; continue; } // clear -> env fallback
    if (spec.enum && !spec.enum.includes(value)) {
      throw new Error(`Invalid value for "${key}".`);
    }
    current[key] = value;
  }

  const target = filePath(opts);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, JSON.stringify(current, null, 2), { mode: 0o600 });
  try { fs.chmodSync(target, 0o600); } catch (_) { /* best effort on platforms without chmod */ }
  return current;
}

/**
 * Resolve a single key: saved value (if non-empty) → env var → null.
 */
function resolve(key, env = process.env, opts = {}) {
  const spec = KEYS[key];
  if (!spec) return null;
  const saved = loadSettings(opts)[key];
  if (saved !== undefined && saved !== null && String(saved) !== '') return String(saved);
  const fromEnv = env[spec.env];
  return fromEnv !== undefined && fromEnv !== null && String(fromEnv) !== '' ? String(fromEnv) : null;
}

/** Resolve every known key into a flat object. */
function resolveAll(env = process.env, opts = {}) {
  const out = {};
  for (const key of Object.keys(KEYS)) out[key] = resolve(key, env, opts);
  return out;
}

function maskHint(value) {
  if (!value) return null;
  const v = String(value);
  return v.length <= 4 ? '••••' : '••••' + v.slice(-4);
}

/**
 * A browser-safe view of the merged config. Secrets are never returned in the
 * clear — only `configured`, `source`, and a short `hint`. Non-secret values
 * (provider, model, URLs, username, threshold) are returned so the UI can
 * pre-fill the form.
 */
function maskedView(env = process.env, opts = {}) {
  const saved = loadSettings(opts);
  const view = {};
  for (const [key, spec] of Object.entries(KEYS)) {
    const savedVal = saved[key];
    const hasSaved = savedVal !== undefined && savedVal !== null && String(savedVal) !== '';
    const envVal = env[spec.env];
    const hasEnv = envVal !== undefined && envVal !== null && String(envVal) !== '';
    const value = hasSaved ? String(savedVal) : (hasEnv ? String(envVal) : null);
    const entry = {
      env: spec.env,
      secret: !!spec.secret,
      configured: hasSaved || hasEnv,
      source: hasSaved ? 'settings' : (hasEnv ? 'env' : 'none')
    };
    if (spec.secret) {
      entry.hint = value ? maskHint(value) : null;
    } else {
      entry.value = value; // safe to expose
    }
    view[key] = entry;
  }
  return view;
}

module.exports = { KEYS, loadSettings, saveSettings, resolve, resolveAll, maskedView, filePath };
