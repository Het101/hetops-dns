const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Database = require('better-sqlite3');
const { createBackups, verify, rotate, signV4 } = require('../backup');

function liveDb() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hetops-backup-'));
  const file = path.join(dir, 'live.db');
  const db = new Database(file);
  db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT); CREATE TABLE alerts (id INTEGER PRIMARY KEY, domain TEXT);");
  const ins = db.prepare('INSERT INTO users (email) VALUES (?)');
  for (let i = 0; i < 25; i++) ins.run(`u${i}@example.com`);
  db.prepare("INSERT INTO alerts (domain) VALUES ('example.com')").run();
  return { db, file, dir };
}

test('a backup is a restorable copy: integrity ok and the same rows as the live database', async () => {
  const { db, file, dir } = liveDb();
  const b = createBackups({ db, dbPath: file, env: {}, log: { info() {}, error() {} } });
  const s = await b.run();
  assert.equal(s.ok, true, s.error);
  assert.equal(s.offsite, 'not configured');
  assert.deepEqual(s.counts, { users: 25, alerts: 1 });
  // The restore drill, end to end: restore the snapshot as a fresh database and read it.
  const restored = path.join(dir, 'restored.db');
  fs.copyFileSync(path.join(b.dir, s.file), restored);
  const r = new Database(restored, { readonly: true });
  assert.equal(r.prepare('SELECT COUNT(*) n FROM users').get().n, 25);
  assert.equal(r.prepare('SELECT email FROM users WHERE id = 25').get().email, 'u24@example.com');
  r.close();
});

test('a corrupt snapshot fails the drill', () => {
  const { dir } = liveDb();
  const bad = path.join(dir, 'bad.db');
  fs.writeFileSync(bad, Buffer.concat([Buffer.from('SQLite format 3\0'), crypto.randomBytes(4096)]));
  assert.throws(() => { const v = verify(bad); if (!v.ok) throw new Error('drill failed'); });
});

test('rotation keeps the newest N snapshots', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hetops-rot-'));
  for (let d = 1; d <= 5; d++) fs.writeFileSync(path.join(dir, `hetops-2026100${d}-030000.db`), '');
  fs.writeFileSync(path.join(dir, 'notes.txt'), 'leave me');
  const gone = rotate(dir, 3);
  assert.deepEqual(gone, ['hetops-20261001-030000.db', 'hetops-20261002-030000.db']);
  assert.ok(fs.existsSync(path.join(dir, 'notes.txt')));
});

test('the offsite upload is a signed PUT of the snapshot', async () => {
  const { db, file } = liveDb();
  const calls = [];
  const env = { S3_ENDPOINT: 'https://acct.r2.cloudflarestorage.com', S3_BUCKET: 'backups', S3_ACCESS_KEY_ID: 'AKIDTEST', S3_SECRET_ACCESS_KEY: 'secret' };
  const b = createBackups({ db, dbPath: file, env, log: { info() {}, error() {} }, fetchImpl: async (url, opts) => { calls.push({ url, opts }); return { ok: true, status: 200 }; } });
  const s = await b.run();
  assert.equal(s.ok, true, s.error); assert.equal(s.offsite, 'uploaded');
  assert.equal(calls.length, 1);
  assert.match(calls[0].url, /^https:\/\/acct\.r2\.cloudflarestorage\.com\/backups\/hetops-dns\/hetops-\d{8}-\d{6}\.db$/);
  assert.equal(calls[0].opts.method, 'PUT');
  assert.match(calls[0].opts.headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKIDTEST\/\d{8}\/auto\/s3\/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/);
});

// AWS's published SigV4 test suite, "get-vanilla".
test('SigV4 matches the AWS test vector', () => {
  const { signature } = signV4({
    method: 'GET', url: 'https://example.amazonaws.com/', headers: {},
    payloadHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
    region: 'us-east-1', service: 'service', amzDate: '20150830T123600Z',
  });
  assert.equal(signature, '5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31');
});

const crypto = require('node:crypto');

test('the last result survives a restart, so health is not empty after a deploy', async () => {
  const { db, file } = liveDb();
  const first = createBackups({ db, dbPath: file, env: {}, log: { info() {}, error() {} } });
  const ran = await first.run();
  const again = createBackups({ db, dbPath: file, env: {}, log: { info() {}, error() {} } });   // a fresh process
  assert.equal(again.status().ok, true);
  assert.equal(again.status().at, ran.at);
  assert.equal(again.status().file, ran.file);
  assert.equal(again.status().offsite, ran.offsite);
});
