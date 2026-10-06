// A database from before hashing must keep working after the upgrade: existing
// sessions, API keys and unexpired sign-in links stay valid, and the plain values
// are gone from the file.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const Database = require('better-sqlite3');

const file = path.join(os.tmpdir(), `hetops-migrate-${process.pid}-${Date.now()}.db`);
const old = new Database(file);
old.exec(`
  CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, created_at INTEGER NOT NULL);
  CREATE TABLE login_tokens (token TEXT PRIMARY KEY, email TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE sessions (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE api_keys (key TEXT PRIMARY KEY, user_id INTEGER NOT NULL, label TEXT, created_at INTEGER NOT NULL, last_used INTEGER);
`);
const later = Date.now() + 60 * 60 * 1000;
old.prepare('INSERT INTO users (id, email, created_at) VALUES (1, ?, ?)').run('old@example.com', Date.now());
old.prepare('INSERT INTO login_tokens VALUES (?, ?, ?, 0)').run('oldtoken', 'old@example.com', later);
old.prepare('INSERT INTO sessions VALUES (?, 1, ?, ?)').run('oldsession', Date.now(), later);
old.prepare('INSERT INTO api_keys (key, user_id, label, created_at) VALUES (?, 1, ?, ?)').run('hk_0123456789abcdef', 'old', Date.now());
old.close();

process.env.DB_PATH = file;
const store = require('../db');

test('existing secrets keep working after the upgrade', () => {
  assert.equal(store.getSession('oldsession').email, 'old@example.com');
  assert.equal(store.apiKeyUser('hk_0123456789abcdef'), 1);
  assert.equal(store.listApiKeys(1)[0].hint, 'hk_0123456…cdef');
  assert.equal(store.consumeLoginToken('oldtoken'), 'old@example.com');
});

test('and the plain values are gone from the file', () => {
  const raw = new Database(file, { readonly: true });
  const all = [
    ...raw.prepare('SELECT token AS v FROM login_tokens').all(),
    ...raw.prepare('SELECT id AS v FROM sessions').all(),
    ...raw.prepare('SELECT key AS v FROM api_keys').all(),
  ].map((r) => r.v);
  for (const plain of ['oldtoken', 'oldsession', 'hk_0123456789abcdef']) assert.ok(!all.includes(plain), plain);
  assert.equal(raw.pragma('user_version', { simple: true }), 1);
  raw.close();
});
