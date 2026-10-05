// The sign-in link must never be built from request headers in production: a forged
// Host or X-Forwarded-Host would email someone a valid token on an attacker's site.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');

process.env.NODE_ENV = 'production';
delete process.env.APP_URL;
process.env.DB_PATH = path.join(os.tmpdir(), `hetops-linkhost-${process.pid}.db`);
const mailer = require('../email');
const sent = [];
mailer.sendMagicLink = async (to, url) => { sent.push(url); };
const { app } = require('../server');

let server, base;
before(async () => { await new Promise((r) => { server = app.listen(0, '127.0.0.1', r); }); base = `http://127.0.0.1:${server.address().port}`; });
after(() => new Promise((r) => server.close(r)));

test('a forged Host or X-Forwarded-Host does not change the emailed link', async () => {
  const res = await fetch(`${base}/api/auth/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Host: 'evil.example', 'X-Forwarded-Host': 'evil.example' },
    body: JSON.stringify({ email: 'victim@example.com' }),
  });
  assert.equal(res.status, 200);
  assert.equal(sent.length, 1);
  assert.ok(sent[0].startsWith('https://dns.hetops.dev/api/auth/verify?token='), sent[0]);
});
