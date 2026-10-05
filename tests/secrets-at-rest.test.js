// Sign-in tokens, sessions and API keys must be useless to someone holding a copy
// of the database file: only hashes are stored.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const Database = require('better-sqlite3');

process.env.DB_PATH = path.join(os.tmpdir(), `hetops-secrets-${process.pid}.db`);
const store = require('../db');
const raw = new Database(process.env.DB_PATH, { readonly: true });
const stored = (table, col) => raw.prepare(`SELECT ${col} AS v FROM ${table}`).all().map((r) => r.v);

test('sign-in tokens: only the hash is stored, and the link still works once', () => {
  const token = store.createLoginToken('a@example.com');
  assert.ok(!stored('login_tokens', 'token').includes(token));
  assert.equal(store.consumeLoginToken(token), 'a@example.com');
  assert.equal(store.consumeLoginToken(token), null, 'single use');
});

test('sessions: the cookie value is not stored, and sign-out works', () => {
  const u = store.upsertUser('b@example.com');
  const sid = store.createSession(u.id);
  assert.ok(!stored('sessions', 'id').includes(sid));
  assert.equal(store.getSession(sid).email, 'b@example.com');
  const [hash] = stored('sessions', 'id');
  assert.equal(store.getSession(hash), null, 'the stored value is not a session id');
  store.destroySession(sid);
  assert.equal(store.getSession(sid), null);
});

test('API keys: shown once, listed by hint, revoked by id', () => {
  const u = store.upsertUser('c@example.com');
  const key = store.createApiKey(u.id, 'ci');
  assert.ok(!stored('api_keys', 'key').includes(key));
  assert.equal(store.apiKeyUser(key), u.id);
  assert.equal(store.apiKeyExists(key), true);

  const [listed] = store.listApiKeys(u.id);
  assert.equal(listed.hint, `${key.slice(0, 10)}…${key.slice(-4)}`);
  assert.equal(JSON.stringify(listed).includes(key), false, 'the list never contains the key');
  assert.equal(store.apiKeyUser(listed.id), null, 'the id is not usable as a key');

  store.deleteApiKey(u.id, listed.id);
  assert.equal(store.apiKeyUser(key), null);
});
