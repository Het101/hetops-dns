const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.DB_PATH = path.join(os.tmpdir(), `hetops-dmarc-${process.pid}-${Date.now()}.db`);
process.env.DMARC_INGEST_SECRET = 'test-secret-0123456789';
process.env.PLAN_OVERRIDES = 'ingest@example.com:pro';   // automatic collection is a paid feature
const store = require('../db');
const { app } = require('../server');
const { extractReports, tokenFromAddress } = require('../dmarc-ingest');

const zip = fs.readFileSync(path.join(__dirname, 'fixtures', 'dmarc-sample.zip'));
// A report email as Google sends it: text part plus a base64 zip attachment.
const email = (to, attachment = zip) => [
  'From: noreply-dmarc-support@google.com',
  `To: ${to}`,
  'Subject: Report domain: example.com Submitter: google.com Report-ID: 1234567890123456789',
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="b1"',
  '',
  '--b1',
  'Content-Type: text/plain; charset=UTF-8',
  '',
  'This is an aggregate report from google.com.',
  '--b1',
  'Content-Type: application/zip; name="google.com!example.com!1759449600!1759535999.zip"',
  'Content-Disposition: attachment; filename="google.com!example.com!1759449600!1759535999.zip"',
  'Content-Transfer-Encoding: base64',
  '',
  attachment.toString('base64').replace(/.{76}/g, '$&\r\n'),
  '--b1--',
  '',
].join('\r\n');

test('extractReports pulls the report out of a real-format email', async () => {
  const out = await extractReports(email('dmarc-abc@hetops.dev'));
  assert.equal(out.reports.length, 1);
  assert.equal(out.reports[0].domain, 'example.com');
  assert.equal(out.reports[0].records.length, 3);
  const none = await extractReports(email('x@hetops.dev').replace(/Content-Type: application\/zip[\s\S]*--b1--/, '--b1--'));
  assert.equal(none.reports.length, 0);
});

test('tokenFromAddress accepts only our format', () => {
  assert.equal(tokenFromAddress('dmarc-0a1b2c3d4e5f6a7b@hetops.dev'), '0a1b2c3d4e5f6a7b');
  assert.equal(tokenFromAddress('DMARC-0A1B2C3D4E5F6A7B@HETOPS.DEV'), '0a1b2c3d4e5f6a7b');
  assert.equal(tokenFromAddress('someone@hetops.dev'), null);
  assert.equal(tokenFromAddress('dmarc-short@hetops.dev'), null);
});

test('one address per user; the same report is stored once', () => {
  const u = store.upsertUser('dm@example.com');
  const t1 = store.dmarcTokenFor(u.id), t2 = store.dmarcTokenFor(u.id);
  assert.equal(t1, t2);
  assert.equal(store.userForDmarcToken(t1), u.id);
  assert.equal(store.userForDmarcToken('nope'), null);
});

let server, base;
before(async () => { await new Promise((r) => { server = app.listen(0, '127.0.0.1', r); }); base = `http://127.0.0.1:${server.address().port}`; });
after(() => new Promise((r) => server.close(r)));

test('POST /api/dmarc/ingest: secret required, unknown address ignored, known address stored once', async () => {
  const u = store.upsertUser('ingest@example.com');
  const addr = `dmarc-${store.dmarcTokenFor(u.id)}@hetops.dev`;
  const post = (to, secret = process.env.DMARC_INGEST_SECRET) => fetch(`${base}/api/dmarc/ingest`, {
    method: 'POST', headers: { Authorization: `Bearer ${secret}`, 'X-Envelope-To': to, 'Content-Type': 'message/rfc822' }, body: email(to),
  });

  assert.equal((await post(addr, 'wrong')).status, 401);
  const unknown = await post('dmarc-ffffffffffffffff@hetops.dev');
  assert.equal(unknown.status, 202);
  assert.deepEqual(await unknown.json(), { stored: 0 });

  assert.deepEqual(await (await post(addr)).json(), { stored: 1 });
  assert.deepEqual(await (await post(addr)).json(), { stored: 0 }, 'duplicate report ignored');
  const saved = store.listDmarcReports(u.id);
  assert.equal(saved.length, 1);
  assert.equal(saved[0].records.length, 3);

  // A free account keeps its address but stores nothing until it upgrades.
  const free = store.upsertUser('free@example.com');
  const freeAddr = `dmarc-${store.dmarcTokenFor(free.id)}@hetops.dev`;
  assert.deepEqual(await (await post(freeAddr)).json(), { stored: 0 });
  assert.equal(store.listDmarcReports(free.id).length, 0);

  assert.equal((await fetch(`${base}/api/dmarc/reports`)).status, 401);
  assert.equal((await fetch(`${base}/api/dmarc/address`)).status, 401);
});
