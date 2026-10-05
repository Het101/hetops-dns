const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeDomain,
  parseDomains,
  isBlockedIPv4,
  isBlockedIp,
  cacheKeyFor,
  parseWhoisExpiryDays,
  diffStatus,
  calculateSslLabsGrade,
} = require('../server');

test('normalizeDomain strips protocol, path and trailing dot', () => {
  assert.equal(normalizeDomain('https://Example.COM/some/path?q=1'), 'example.com');
  assert.equal(normalizeDomain('example.com.'), 'example.com');
  assert.equal(normalizeDomain('  example.com  '), 'example.com');
});

test('normalizeDomain rejects invalid input', () => {
  assert.equal(normalizeDomain('a'.repeat(257) + '.com'), '');
  assert.equal(normalizeDomain('ex ample.com'), '');
  assert.equal(normalizeDomain('single-label'), '');
  assert.equal(normalizeDomain('evil.com`whoami`'), '');
  assert.equal(normalizeDomain(42), '');
  assert.equal(normalizeDomain(''), '');
});

test('parseDomains dedupes, splits strings, caps at 20', () => {
  assert.deepEqual(parseDomains('a.com', ['a.com', 'b.com']), ['a.com', 'b.com']);
  assert.deepEqual(parseDomains('', 'a.com, b.com\nc.com d.com'), ['a.com', 'b.com', 'c.com', 'd.com']);
  const many = Array.from({ length: 30 }, (_, i) => `d${i}.com`);
  assert.equal(parseDomains('', many).length, 20);
  assert.deepEqual(parseDomains('', ['!!invalid!!']), []);
});

test('isBlockedIPv4 blocks private/loopback/metadata/CGNAT ranges', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.5.5', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0']) {
    assert.equal(isBlockedIPv4(ip), true, `${ip} should be blocked`);
  }
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34']) {
    assert.equal(isBlockedIPv4(ip), false, `${ip} should be allowed`);
  }
});

test('isBlockedIp handles IPv6 loopback, link-local, ULA and mapped IPv4', () => {
  for (const ip of ['::1', 'fe80::1', 'fd00::1', '::ffff:10.0.0.1', '::ffff:127.0.0.1']) {
    assert.equal(isBlockedIp(ip), true, `${ip} should be blocked`);
  }
  assert.equal(isBlockedIp('2606:4700:4700::1111'), false);
  assert.equal(isBlockedIp('not-an-ip'), false);
});

test('parseWhoisExpiryDays parses common registrar formats', () => {
  const future = new Date(Date.now() + 90 * 86400000).toISOString();
  const days = parseWhoisExpiryDays({ rawData: `Registry Expiry Date: ${future}` });
  assert.ok(days >= 89 && days <= 90, `expected ~90, got ${days}`);

  const past = new Date(Date.now() - 10 * 86400000).toISOString();
  assert.ok(parseWhoisExpiryDays({ rawData: `Registrar Registration Expiration Date: ${past}` }) < 0);

  assert.ok(parseWhoisExpiryDays({ rawData: 'paid-till: 2099-01-01T00:00:00Z' }) > 0);
  assert.equal(parseWhoisExpiryDays({ rawData: 'no expiry here' }), null);
  assert.equal(parseWhoisExpiryDays(null), null);
  assert.equal(parseWhoisExpiryDays({ error: true, rawData: 'Registry Expiry Date: 2099-01-01' }), null);
});

test('diffStatus emits threshold and change alerts', () => {
  assert.deepEqual(diffStatus({}, { sslDays: 5 }), []); // no baseline → no alerts
  assert.deepEqual(diffStatus(null, { sslDays: 5 }), []);

  const ch = diffStatus({ sslDays: 31 }, { sslDays: 29 });
  assert.equal(ch.length, 1);
  assert.match(ch[0], /within 30 days/);

  assert.match(diffStatus({ sslDays: 1 }, { sslDays: -1 })[0], /expired/i);
  assert.match(diffStatus({ blacklisted: false }, { blacklisted: true })[0], /blacklisted/);
  assert.match(
    diffStatus({ aRecords: ['1.2.3.4'] }, { aRecords: ['5.6.7.8'] })[0],
    /A record changed/
  );
  assert.match(diffStatus({ grade: 'A' }, { grade: 'B' })[0], /TLS grade changed A → B/);
  assert.deepEqual(diffStatus({ sslDays: 60 }, { sslDays: 55 }), []);
});

test('cacheKeyFor includes result-shaping body fields (cache-poisoning regression)', () => {
  const req = (body, path = '/dns-lookup', method = 'POST') => ({ method, path, body });
  const a = cacheKeyFor(req({ domain: 'example.com', types: ['A'] }));
  const mx = cacheKeyFor(req({ domain: 'example.com', types: ['MX'] }));
  assert.ok(a && mx && a !== mx, 'different `types` must produce different cache keys');

  const p1 = cacheKeyFor(req({ domain: 'example.com', ports: [80] }, '/port-scan'));
  const p2 = cacheKeyFor(req({ domain: 'example.com', ports: [443] }, '/port-scan'));
  assert.notEqual(p1, p2, 'different `ports` must produce different cache keys');

  assert.equal(cacheKeyFor(req({ domain: 'example.com' }, '/dns-lookup', 'GET')), null);
  assert.equal(cacheKeyFor(req({ email: 'a@b.c' }, '/auth/request')), null);
  assert.equal(cacheKeyFor(req({ domain: 'example.com' }, '/history')), null);
  assert.equal(cacheKeyFor(req({})), null);
});

test('computeHealthScore — shared module, full/partial/empty inputs', () => {
  const { computeHealthScore, gradeOf } = require('../public/shared/health-score');

  const full = computeHealthScore({
    dns: { insights: { checks: { spf: true, dmarc: true, caa: true, mx: true } } },
    ssl: { certificate: { daysRemaining: 120 } },
    emailsec: { overallScore: 100 },
    blacklist: { results: [{ listed: false }] },
  });
  assert.equal(full.pct, 100);
  assert.equal(full.grade, 'A+');
  assert.equal(full.breakdown.length, 4);

  const sslOnly = computeHealthScore({ ssl: { certificate: { daysRemaining: 120 } } });
  assert.equal(sslOnly.pct, 100); // 30/30 — failed sections drop out of the total
  assert.equal(sslOnly.tot, 30);

  const weak = computeHealthScore({
    dns: { insights: { checks: { spf: false, dmarc: false, caa: false, mx: true } } },
    ssl: { certificate: { daysRemaining: 10 } },
    emailsec: { overallScore: 20 },
    blacklist: { results: [{ listed: true }] },
  });
  assert.ok(weak.pct < 50, `expected weak pct < 50, got ${weak.pct}`);
  assert.equal(weak.grade, 'D');

  assert.equal(computeHealthScore({}), null);
  assert.equal(computeHealthScore({ dns: { error: 'failed' }, ssl: { error: 'failed' } }), null);

  assert.equal(gradeOf(95), 'A+');
  assert.equal(gradeOf(85), 'A');
  assert.equal(gradeOf(70), 'B');
  assert.equal(gradeOf(50), 'C');
  assert.equal(gradeOf(49), 'D');
});

test('calculateSslLabsGrade boundaries', () => {
  assert.equal(calculateSslLabsGrade(100).letter, 'A+');
  assert.equal(calculateSslLabsGrade(95).letter, 'A');
  assert.equal(calculateSslLabsGrade(80).letter, 'A-');
  assert.equal(calculateSslLabsGrade(70).letter, 'B');
  assert.equal(calculateSslLabsGrade(60).letter, 'C');
  assert.equal(calculateSslLabsGrade(50).letter, 'D');
  assert.equal(calculateSslLabsGrade(40).letter, 'E');
  assert.equal(calculateSslLabsGrade(0).letter, 'F');
});

test('diffStatus watches email authentication and delegation', () => {
  const spfOld = 'v=spf1 include:_spf.google.com -all';
  const spfNew = 'v=spf1 include:_spf.google.com include:mailgun.org -all';

  assert.match(diffStatus({ spf: spfOld }, { spf: '' })[0], /SPF record removed/);
  assert.match(diffStatus({ spf: '' }, { spf: spfOld })[0], /SPF record added/);
  assert.match(diffStatus({ spf: spfOld }, { spf: spfNew })[0], /SPF record changed/);

  assert.match(diffStatus({ dmarcPolicy: 'reject' }, { dmarcPolicy: 'none' })[0], /DMARC policy weakened: reject → none/);
  assert.match(diffStatus({ dmarcPolicy: 'none' }, { dmarcPolicy: 'quarantine' })[0], /DMARC policy tightened: none → quarantine/);
  assert.match(diffStatus({ dmarcPolicy: 'reject' }, { dmarcPolicy: '' })[0], /DMARC record removed/);

  assert.match(diffStatus({ mx: ['a.mx.example'] }, { mx: ['b.mx.example'] })[0], /MX records changed/);
  assert.match(diffStatus({ ns: ['ns1.old.net'] }, { ns: ['ns1.new.net'] })[0], /Nameservers changed/);

  // Unknown (null) on either side never alerts: a failed lookup is not a change.
  assert.deepEqual(diffStatus({ spf: spfOld }, { spf: null }), []);
  assert.deepEqual(diffStatus({ mx: ['a.mx.example'] }, { mx: null }), []);
  // Fields missing from an older baseline never alert on upgrade.
  assert.deepEqual(diffStatus({ sslDays: 60 }, { sslDays: 60, spf: spfOld, dmarcPolicy: 'reject', mx: ['a'], ns: ['b'] }), []);
  // Order of MX/NS answers is not a change.
  assert.deepEqual(diffStatus({ mx: ['a', 'b'] }, { mx: ['b', 'a'] }), []);
});

test('normalizeDomain runs in linear time on pathological dotted input (ReDoS)', () => {
  const start = Date.now();
  assert.equal(normalizeDomain('-.'.repeat(120) + '!'), '');
  assert.ok(Date.now() - start < 200, `took ${Date.now() - start}ms`);
  assert.equal(normalizeDomain('a..example.com'), '');
  assert.equal(normalizeDomain('.example.com'), '');
  assert.equal(normalizeDomain('sub.example.co.uk'), 'sub.example.co.uk');
});

test('EMAIL_RE accepts normal addresses and is linear on long dotted input (ReDoS)', () => {
  const { EMAIL_RE } = require('../server');
  assert.ok(EMAIL_RE.test('a.b+c@mail.example.co.uk'));
  assert.ok(!EMAIL_RE.test('a@example'));
  assert.ok(!EMAIL_RE.test('a@b..com'));
  const start = Date.now();
  assert.ok(!EMAIL_RE.test('a@' + '!.'.repeat(50000) + ' '));
  assert.ok(Date.now() - start < 200, `took ${Date.now() - start}ms`);
});
