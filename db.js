// ── SQLite persistence layer ───────────────────────────────────
// One file-backed database holding users, login tokens, sessions, scan history
// and alert watches. In Docker the file lives under a mounted volume (see
// Dockerfile + DB_PATH) so data survives container restarts.
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'hetops.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT UNIQUE NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS login_tokens (
    token      TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS history (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id  INTEGER NOT NULL,
    domain   TEXT NOT NULL,
    ts       INTEGER NOT NULL,
    snapshot TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_history_user ON history(user_id, ts DESC);

  CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    domain        TEXT NOT NULL,
    email_enabled INTEGER NOT NULL DEFAULT 1,
    last_state    TEXT,
    last_checked  INTEGER,
    created_at    INTEGER NOT NULL,
    UNIQUE(user_id, domain),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    key        TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    label      TEXT,
    created_at INTEGER NOT NULL,
    last_used  INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- Every change the monitor detected, so users can see a history, not just an email.
  CREATE TABLE IF NOT EXISTS alert_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    domain  TEXT NOT NULL,
    ts      INTEGER NOT NULL,
    change  TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_alert_events_user ON alert_events(user_id, ts DESC, id DESC);

  -- DMARC: each user gets one private ingest address (dmarc-<token>@hetops.dev).
  CREATE TABLE IF NOT EXISTS dmarc_addresses (
    user_id    INTEGER PRIMARY KEY,
    token      TEXT UNIQUE NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS dmarc_reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    org         TEXT NOT NULL,
    report_id   TEXT NOT NULL,
    domain      TEXT NOT NULL,
    begin_ts    INTEGER NOT NULL,
    end_ts      INTEGER NOT NULL,
    data        TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    UNIQUE(user_id, org, report_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_dmarc_reports_user ON dmarc_reports(user_id, end_ts DESC);
`);

// Lightweight migrations for columns added after initial release (ignore if present).
for (const col of ['webhook_url TEXT', 'digest_enabled INTEGER DEFAULT 0', 'last_digest INTEGER',
  // billing (Lemon Squeezy)
  'plan TEXT', 'plan_status TEXT', 'plan_ends_at INTEGER', 'ls_customer_id TEXT', 'ls_subscription_id TEXT', 'ls_portal_url TEXT']) {
  try { db.exec(`ALTER TABLE users ADD COLUMN ${col}`); } catch { /* already exists */ }
}

const now = () => Date.now();
const newId = (bytes = 32) => crypto.randomBytes(bytes).toString('hex');

// Sign-in tokens, session ids and API keys are stored as SHA-256 hashes, so a copy
// of this file can't be used to sign in or call the API. They are 20-32 random
// bytes, so a plain hash is enough: there is nothing to brute-force or look up.
const hashSecret = (v) => crypto.createHash('sha256').update(String(v)).digest('hex');
// What the dashboard shows for a key it can no longer read back.
const keyHint = (key) => `${key.slice(0, 10)}…${key.slice(-4)}`;

// One-off: hash the secrets stored in plain text before this version. Nobody is
// signed out and no API key stops working, because lookups hash what they're given.
try { db.exec('ALTER TABLE api_keys ADD COLUMN hint TEXT'); } catch { /* already exists */ }
if (db.pragma('user_version', { simple: true }) < 1) {
  db.transaction(() => {
    for (const { token } of db.prepare('SELECT token FROM login_tokens').all()) {
      db.prepare('UPDATE login_tokens SET token = ? WHERE token = ?').run(hashSecret(token), token);
    }
    for (const { id } of db.prepare('SELECT id FROM sessions').all()) {
      db.prepare('UPDATE sessions SET id = ? WHERE id = ?').run(hashSecret(id), id);
    }
    for (const { key } of db.prepare('SELECT key FROM api_keys').all()) {
      db.prepare('UPDATE api_keys SET key = ?, hint = ? WHERE key = ?').run(hashSecret(key), keyHint(key), key);
    }
    db.pragma('user_version = 1');
  })();
}

// ── Users ──
const _userByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const _insUserIgnore = db.prepare('INSERT INTO users (email, created_at) VALUES (?, ?) ON CONFLICT(email) DO NOTHING');
// Race-safe: INSERT-OR-IGNORE then SELECT, so concurrent first-logins can't crash
// on the UNIQUE(email) constraint and always return the canonical stored row.
function upsertUser(email) {
  _insUserIgnore.run(email, now());
  return _userByEmail.get(email);
}

// ── Login tokens (magic link) ──
const _insToken = db.prepare('INSERT INTO login_tokens (token, email, expires_at, used) VALUES (?, ?, ?, 0)');
const _expirePriorTokens = db.prepare('UPDATE login_tokens SET used = 1 WHERE email = ? AND used = 0');
// Atomic single-use consumption: only the first caller flips used 0→1 (changes===1).
const _consumeToken = db.prepare('UPDATE login_tokens SET used = 1 WHERE token = ? AND used = 0 AND expires_at >= ?');
const _getTokenEmail = db.prepare('SELECT email FROM login_tokens WHERE token = ?');
function createLoginToken(email, ttlMs = 15 * 60 * 1000) {
  _expirePriorTokens.run(email);            // invalidate any outstanding links for this email
  const token = newId(24);
  _insToken.run(hashSecret(token), email, now() + ttlMs);
  return token;
}
function consumeLoginToken(token) {
  token = hashSecret(token);
  const info = _consumeToken.run(token, now());
  if (info.changes !== 1) return null;      // already used / expired / unknown — atomic guard
  const row = _getTokenEmail.get(token);
  return row ? row.email : null;
}

// ── Sessions ──
const _insSession = db.prepare('INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)');
const _getSession = db.prepare('SELECT s.id, s.user_id, s.expires_at, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?');
const _delSession = db.prepare('DELETE FROM sessions WHERE id = ?');
function createSession(userId, ttlMs = 30 * 24 * 60 * 60 * 1000) {
  const id = newId(32);
  _insSession.run(hashSecret(id), userId, now(), now() + ttlMs);
  return id;
}
function getSession(id) {
  if (!id) return null;
  const row = _getSession.get(hashSecret(id));
  if (!row || row.expires_at < now()) return null;
  return row; // { id (hashed), user_id, expires_at, email }
}
function destroySession(id) { if (id) _delSession.run(hashSecret(id)); }

// ── History ──
const _insHistory = db.prepare('INSERT INTO history (user_id, domain, ts, snapshot) VALUES (?, ?, ?, ?)');
const _listHistory = db.prepare('SELECT domain, ts, snapshot FROM history WHERE user_id = ? ORDER BY ts DESC LIMIT ?');
const _clearHistory = db.prepare('DELETE FROM history WHERE user_id = ?');
const _trimHistory = db.prepare('DELETE FROM history WHERE user_id = ? AND id NOT IN (SELECT id FROM history WHERE user_id = ? ORDER BY ts DESC LIMIT ?)');
function addHistory(userId, domain, ts, snapshotObj) {
  _insHistory.run(userId, domain, ts, JSON.stringify(snapshotObj || {}));
  _trimHistory.run(userId, userId, 100);
}
function listHistory(userId, limit = 60) {
  // Spread snapshot FIRST so the authoritative domain/ts columns can't be
  // overridden by client-supplied fields inside the stored snapshot JSON.
  return _listHistory.all(userId, limit).map(r => ({ ...safeParse(r.snapshot), domain: r.domain, ts: r.ts }));
}
function clearHistory(userId) { _clearHistory.run(userId); }

// ── Alerts ──
const _insAlert = db.prepare(`INSERT INTO alerts (user_id, domain, email_enabled, created_at)
  VALUES (?, ?, ?, ?) ON CONFLICT(user_id, domain) DO UPDATE SET email_enabled = excluded.email_enabled`);
const _listAlertsForUser = db.prepare('SELECT id, domain, email_enabled, last_state, last_checked FROM alerts WHERE user_id = ? ORDER BY created_at DESC');
const _delAlert = db.prepare('DELETE FROM alerts WHERE user_id = ? AND domain = ?');
const _allAlerts = db.prepare('SELECT a.id, a.user_id, a.domain, a.email_enabled, a.last_state, u.email, u.webhook_url FROM alerts a JOIN users u ON u.id = a.user_id');
const _updAlertState = db.prepare('UPDATE alerts SET last_state = ?, last_checked = ? WHERE id = ?');
function addAlert(userId, domain, emailEnabled = 1) {
  _insAlert.run(userId, domain, emailEnabled ? 1 : 0, now());
}
function listAlerts(userId) {
  return _listAlertsForUser.all(userId).map(a => ({
    domain: a.domain, emailEnabled: !!a.email_enabled,
    lastChecked: a.last_checked, last: safeParse(a.last_state),
  }));
}
function removeAlert(userId, domain) { _delAlert.run(userId, domain); }
function allAlerts() {
  return _allAlerts.all().map(a => ({
    id: a.id, userId: a.user_id, domain: a.domain,
    emailEnabled: !!a.email_enabled, email: a.email, webhookUrl: a.webhook_url || null,
    last: safeParse(a.last_state),
  }));
}
function updateAlertState(id, stateObj) { _updAlertState.run(JSON.stringify(stateObj || {}), now(), id); }

// ── Alert events (change history) ──
const ALERT_EVENT_CAP = 500; // per user; oldest are dropped
const _insEvent = db.prepare('INSERT INTO alert_events (user_id, domain, ts, change) VALUES (?, ?, ?, ?)');
const _listEvents = db.prepare('SELECT domain, ts, change FROM alert_events WHERE user_id = ? ORDER BY ts DESC, id DESC LIMIT ?');
const _trimEvents = db.prepare(`DELETE FROM alert_events WHERE user_id = ? AND id NOT IN
  (SELECT id FROM alert_events WHERE user_id = ? ORDER BY ts DESC, id DESC LIMIT ${ALERT_EVENT_CAP})`);
const addAlertEvents = db.transaction((userId, domain, changes) => {
  if (!changes || !changes.length) return;
  const ts = now();
  for (const c of changes) _insEvent.run(userId, domain, ts, String(c));
  _trimEvents.run(userId, userId);
});
function listAlertEvents(userId, limit = 100) { return _listEvents.all(userId, Math.min(limit, ALERT_EVENT_CAP)); }

// ── DMARC addresses and reports ──
const _dmarcTok = db.prepare('SELECT token FROM dmarc_addresses WHERE user_id = ?');
const _insDmarcTok = db.prepare('INSERT OR IGNORE INTO dmarc_addresses (user_id, token, created_at) VALUES (?, ?, ?)');
const _dmarcUser = db.prepare('SELECT user_id FROM dmarc_addresses WHERE token = ?');
const _insDmarcReport = db.prepare(`INSERT OR IGNORE INTO dmarc_reports
  (user_id, org, report_id, domain, begin_ts, end_ts, data, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
const _listDmarc = db.prepare('SELECT data FROM dmarc_reports WHERE user_id = ? AND end_ts >= ? ORDER BY end_ts DESC LIMIT ?');
function dmarcTokenFor(userId) {
  _insDmarcTok.run(userId, newId(8), now());   // 16 hex chars; no-op if the user already has one
  return _dmarcTok.get(userId).token;
}
function userForDmarcToken(token) { const r = token && _dmarcUser.get(String(token).toLowerCase()); return r ? r.user_id : null; }
// Returns true if stored, false if this report was already received.
function addDmarcReport(userId, r) {
  return _insDmarcReport.run(userId, r.org || '', r.reportId || `${r.begin}-${r.end}`, r.domain || '',
    r.begin || 0, r.end || 0, JSON.stringify(r), now()).changes > 0;
}
function listDmarcReports(userId, sinceTs = 0, limit = 500) {
  return _listDmarc.all(userId, sinceTs, limit).map((x) => safeParse(x.data));
}

// ── User settings (webhook, digest) ──
const _getUser = db.prepare(`SELECT id, email, webhook_url, digest_enabled, last_digest,
  plan, plan_status, plan_ends_at, ls_customer_id, ls_subscription_id, ls_portal_url FROM users WHERE id = ?`);
const _setBilling = db.prepare(`UPDATE users SET plan = ?, plan_status = ?, plan_ends_at = ?,
  ls_customer_id = COALESCE(?, ls_customer_id), ls_subscription_id = COALESCE(?, ls_subscription_id),
  ls_portal_url = COALESCE(?, ls_portal_url) WHERE id = ?`);
function setBilling(id, b) { return _setBilling.run(b.plan, b.status, b.endsAt, b.customerId, b.subscriptionId, b.portalUrl, id).changes > 0; }
const _setWebhook = db.prepare('UPDATE users SET webhook_url = ? WHERE id = ?');
const _setDigest = db.prepare('UPDATE users SET digest_enabled = ? WHERE id = ?');
const _setLastDigest = db.prepare('UPDATE users SET last_digest = ? WHERE id = ?');
const _digestUsers = db.prepare('SELECT id, email, last_digest FROM users WHERE digest_enabled = 1');
function getUser(id) { return _getUser.get(id); }
function setWebhook(id, url) { _setWebhook.run(url || null, id); }
function setDigest(id, on) { _setDigest.run(on ? 1 : 0, id); }
function markDigestSent(id) { _setLastDigest.run(now(), id); }
function digestUsers() { return _digestUsers.all(); }

// ── API keys ──
const _insApiKey = db.prepare('INSERT INTO api_keys (key, hint, user_id, label, created_at) VALUES (?, ?, ?, ?, ?)');
// `id` is the key's hash: enough to revoke it, useless as a key.
const _listApiKeys = db.prepare('SELECT key AS id, hint, label, created_at, last_used FROM api_keys WHERE user_id = ? ORDER BY created_at DESC');
const _delApiKey = db.prepare('DELETE FROM api_keys WHERE user_id = ? AND key = ?');
const _apiKeyOwner = db.prepare('SELECT user_id FROM api_keys WHERE key = ?');
const _apiKeyExists = db.prepare('SELECT 1 AS ok FROM api_keys WHERE key = ?');
const _touchApiKey = db.prepare('UPDATE api_keys SET last_used = ? WHERE key = ?');
function apiKeyExists(key) { return key ? !!_apiKeyExists.get(hashSecret(key)) : false; }
function createApiKey(userId, label) {
  const key = 'hk_' + newId(20);   // returned once; only its hash is kept
  _insApiKey.run(hashSecret(key), keyHint(key), userId, (label || '').slice(0, 60), now());
  return key;
}
function listApiKeys(userId) { return _listApiKeys.all(userId); }
function deleteApiKey(userId, id) { _delApiKey.run(userId, id); }
function apiKeyUser(key) {
  if (!key) return null;
  const h = hashSecret(key);
  const r = _apiKeyOwner.get(h);
  if (r) { _touchApiKey.run(now(), h); return r.user_id; }
  return null;
}

// Periodic cleanup of expired tokens/sessions.
const _gcTokens = db.prepare('DELETE FROM login_tokens WHERE expires_at < ?');
const _gcSessions = db.prepare('DELETE FROM sessions WHERE expires_at < ?');
function gc() { _gcTokens.run(now()); _gcSessions.run(now()); }
setInterval(gc, 60 * 60 * 1000).unref();

function safeParse(s) { try { return s ? JSON.parse(s) : {}; } catch { return {}; } }

module.exports = {
  db, DB_PATH,
  upsertUser,
  createLoginToken, consumeLoginToken,
  createSession, getSession, destroySession,
  addHistory, listHistory, clearHistory,
  addAlert, listAlerts, removeAlert, allAlerts, updateAlertState,
  addAlertEvents, listAlertEvents, ALERT_EVENT_CAP,
  dmarcTokenFor, userForDmarcToken, addDmarcReport, listDmarcReports,
  getUser, setWebhook, setDigest, markDigestSent, digestUsers, setBilling,
  createApiKey, listApiKeys, deleteApiKey, apiKeyUser, apiKeyExists,
};
