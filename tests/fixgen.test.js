const { test } = require('node:test');
const assert = require('node:assert/strict');
const { buildHeaderFix, PLATFORMS } = require('../public/shared/fix-generator');

const check = (passed, present = passed, extra = {}) => ({ passed, present, deprecated: false, ...extra });

const sample = {
  'Strict-Transport-Security': check(false),
  'Content-Security-Policy': check(true),
  'X-Content-Type-Options': check(true),
  'X-Frame-Options': check(false),
  'X-XSS-Protection': check(true),
  'Referrer-Policy': check(true),
  'Permissions-Policy': check(false),
  'Cache-Control': check(false),
  'X-Powered-By': check(false, true),
  'Server': check(false, false),
  'Public-Key-Pins': check(false, true, { deprecated: true }),
};

test('only failing protective headers are added; leaking and deprecated ones removed', () => {
  const fix = buildHeaderFix(sample);
  assert.deepEqual(fix.add.map((h) => h.name), ['Strict-Transport-Security', 'X-Frame-Options', 'Permissions-Policy']);
  assert.deepEqual(fix.remove, ['X-Powered-By', 'Public-Key-Pins']);   // Server is not present, so nothing to remove
  assert.ok(!fix.add.some((h) => h.name === 'Cache-Control'), 'cache policy is site-specific; never generated');
  assert.ok(fix.add.every((h) => h.value && h.why));
});

test('every platform snippet carries every change', () => {
  const fix = buildHeaderFix(sample);
  for (const p of PLATFORMS) {
    const out = fix.snippets[p.id];
    assert.ok(out && out.length > 20, `${p.id} snippet`);
    for (const h of fix.add) assert.ok(out.includes(h.name), `${p.id} adds ${h.name}`);
  }
  assert.match(fix.snippets.nginx, /add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;/);
  assert.match(fix.snippets.apache, /Header always unset X-Powered-By/);
  // Vercel config must be valid JSON.
  const vercel = JSON.parse(fix.snippets.vercel);
  assert.equal(vercel.headers[0].source, '/(.*)');
  assert.equal(vercel.headers[0].headers.length, 3);
});

test('nothing to fix yields an empty result', () => {
  const allGood = Object.fromEntries(Object.keys(sample).map((k) => [k, check(true)]));
  allGood['X-Powered-By'] = check(false, false);
  allGood['Server'] = check(false, false);
  allGood['Public-Key-Pins'] = check(false, false, { deprecated: true });
  const fix = buildHeaderFix(allGood);
  assert.equal(fix.add.length, 0);
  assert.equal(fix.remove.length, 0);
  assert.equal(fix.empty, true);
});
