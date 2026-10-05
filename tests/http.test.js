const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { app } = require('../server');
const pkg = require('../package.json');

let server;
let base;

before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((resolve) => server.close(resolve)));

test('GET /api/health returns ok and the package.json version', async () => {
  const r = await fetch(`${base}/api/health`);
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.status, 'ok');
  assert.equal(body.version, pkg.version);
});

test('POST /api/dns-lookup without a domain returns 400', async () => {
  const r = await fetch(`${base}/api/dns-lookup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(r.status, 400);
  const body = await r.json();
  assert.ok(body.error);
});

test('POST /api/dns-lookup with an invalid domain returns 400', async () => {
  const r = await fetch(`${base}/api/dns-lookup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain: '!!not-a-domain!!' }),
  });
  assert.equal(r.status, 400);
});

test('ssrfGuard rejects internal targets via `domain` (403)', async () => {
  for (const domain of ['127.0.0.1', '169.254.169.254', '10.0.0.1']) {
    const r = await fetch(`${base}/api/dns-lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    assert.equal(r.status, 403, `${domain} should be rejected`);
  }
});

test('ssrfGuard rejects internal targets smuggled via `domains` array (bypass regression)', async () => {
  const r = await fetch(`${base}/api/dns-lookup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain: 'example.com', domains: ['169.254.169.254'] }),
  });
  assert.equal(r.status, 403);
});

test('unknown /api routes return JSON 404, not the SPA shell', async () => {
  const r = await fetch(`${base}/api/does-not-exist`);
  assert.equal(r.status, 404);
  assert.match(r.headers.get('content-type') || '', /application\/json/);
  const body = await r.json();
  assert.ok(body.error);
});

test('auth-required routes reject anonymous requests', async () => {
  for (const path of ['/api/history', '/api/alerts', '/api/alerts/events', '/api/keys', '/api/settings']) {
    const r = await fetch(`${base}${path}`);
    assert.equal(r.status, 401, `${path} should require auth`);
  }
});

test('POST /api/scan validates input without running checks', async () => {
  const missing = await fetch(`${base}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(missing.status, 400);

  const badChecks = await fetch(`${base}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain: 'example.com', checks: ['nope'] }),
  });
  assert.equal(badChecks.status, 400);
  const body = await badChecks.json();
  assert.match(body.error, /Available:/);
});

test('cross-origin requests from unknown origins are rejected', async () => {
  const r = await fetch(`${base}/api/health`, { headers: { Origin: 'https://evil.example' } });
  assert.equal(r.status, 403);
});

test('/api/redirect refuses an internal `url` (it bypassed ssrfGuard, which only checks `domain`)', async () => {
  for (const url of [`${base}/api/health`, 'http://169.254.169.254/latest/meta-data/', 'http://[::1]:9/']) {
    const r = await fetch(`${base}/api/redirect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const body = await r.json();
    assert.equal(body.chain.length, 1, url);
    assert.match(body.chain[0].error || '', /not permitted/, url);
    assert.equal(body.chain[0].statusCode, undefined, url);
  }
});

test('/spf-checker serves the SPF checker page and is in the sitemap', async () => {
  const r = await fetch(`${base}/spf-checker`);
  assert.equal(r.status, 200);
  assert.match(await r.text(), /<title>SPF Record Checker/);
  const sm = await (await fetch(`${base}/sitemap.xml`)).text();
  assert.match(sm, /https:\/\/dns\.hetops\.dev\/spf-checker/);
});

test('a DNS failure is reported as "could not check", never as a missing SPF/DMARC record', async () => {
  const { Resolver } = require('node:dns').promises;
  const real = Resolver.prototype.resolveTxt;
  const fail = (code) => async () => { throw Object.assign(new Error(code), { code }); };
  const check = async () => (await fetch(`${base}/api/email-security`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: 'example.com' }),
  })).json();
  try {
    Resolver.prototype.resolveTxt = fail('ECONNREFUSED');
    const down = await check();
    assert.equal(down.spf.error, 'ECONNREFUSED');
    assert.equal(down.dmarc.error, 'ECONNREFUSED');
    assert.ok(!down.spf.issues.includes('No SPF record found'), 'must not claim the record is missing');
    assert.ok(!down.dmarc.issues.includes('No DMARC record found'));

    Resolver.prototype.resolveTxt = fail('ENODATA');
    const none = await check();
    assert.equal(none.spf.error, undefined);
    assert.ok(none.spf.issues.includes('No SPF record found'));
    assert.ok(none.dmarc.issues.includes('No DMARC record found'));
  } finally {
    Resolver.prototype.resolveTxt = real;
  }
});

test('the portfolio may call the public API, but never with credentials', async () => {
  const pre = await fetch(`${base}/api/email-security`, { method: 'OPTIONS',
    headers: { Origin: 'https://hetops.dev', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' } });
  assert.ok(pre.status < 400, `preflight ${pre.status}`);
  assert.equal(pre.headers.get('access-control-allow-origin'), 'https://hetops.dev');
  assert.equal(pre.headers.get('access-control-allow-credentials'), null, 'cookies must never be allowed cross-origin');
  const other = await fetch(`${base}/api/email-security`, { method: 'OPTIONS', headers: { Origin: 'https://evil.example' } });
  assert.equal(other.status, 403);
});
