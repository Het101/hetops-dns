const { test } = require('node:test');
const assert = require('node:assert/strict');
const { analyzeSpf, spfLookupIssues, parseTerms } = require('../spf');

// A fake DNS: name -> TXT strings. Missing names are NXDOMAIN (a void lookup).
const dnsFrom = (zone) => async (name) => {
  if (!(name in zone)) throw Object.assign(new Error('nx'), { code: 'ENOTFOUND' });
  return zone[name].map((s) => [s]);
};

// A provider include that nests three more, as _spf.google.com did until Google
// flattened it: the include costs 4 in total, not 1.
const GOOGLE = {
  '_spf.google.com': ['v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all'],
  '_netblocks.google.com': ['v=spf1 ip4:35.190.247.0/24 ~all'],
  '_netblocks2.google.com': ['v=spf1 ip6:2001:4860:4000::/36 ~all'],
  '_netblocks3.google.com': ['v=spf1 ip4:172.217.0.0/19 ~all'],
};

test('counts lookups inside includes, not just the top-level terms', async () => {
  const resolve = dnsFrom(GOOGLE);
  const a = await analyzeSpf('example.com', resolve, 'v=spf1 include:_spf.google.com -all');
  assert.equal(a.count, 4);
  assert.deepEqual(a.breakdown, [{ term: 'include:_spf.google.com', cost: 4 }]);
});

test('"all", ip4, ip6 and exp= cost nothing (the old regex counted -all as an "a" lookup)', async () => {
  const a = await analyzeSpf('example.com', dnsFrom({}), 'v=spf1 ip4:1.2.3.4 ip6:::1 exp=explain.example.com -all');
  assert.equal(a.count, 0);
});

test('a, mx, ptr, exists each cost one; a/24 and mx:host count too', async () => {
  const a = await analyzeSpf('example.com', dnsFrom({}), 'v=spf1 a mx a/24 mx:mail.example.com ptr exists:%{i}.x.example.com -all');
  assert.equal(a.count, 6);
});

test('over 10 is reported with the biggest offenders', async () => {
  const zone = { ...GOOGLE,
    'sendgrid.net': ['v=spf1 include:a.sendgrid.net include:b.sendgrid.net ~all'],
    'a.sendgrid.net': ['v=spf1 ip4:1.1.1.1 ~all'], 'b.sendgrid.net': ['v=spf1 ip4:1.1.1.2 ~all'],
    'mailgun.org': ['v=spf1 include:_spf.mailgun.org ~all'], '_spf.mailgun.org': ['v=spf1 ip4:2.2.2.2 ~all'],
  };
  const a = await analyzeSpf('example.com', dnsFrom(zone), 'v=spf1 a mx include:_spf.google.com include:sendgrid.net include:mailgun.org -all');
  assert.equal(a.count, 11);
  const [first] = spfLookupIssues(a);
  assert.match(first, /needs 11 DNS lookups; receivers stop at 10/);
  assert.match(first, /include:_spf\.google\.com \(4\)/);
});

test('void lookups, missing include targets and duplicate records are errors', async () => {
  const zone = { 'dup.example.com': ['v=spf1 -all', 'v=spf1 ~all'] };
  const a = await analyzeSpf('example.com', dnsFrom(zone), 'v=spf1 include:gone1.example include:gone2.example include:gone3.example include:dup.example.com -all');
  assert.equal(a.voidCount, 3);
  const issues = spfLookupIssues(a);
  assert.ok(issues.some((i) => /3 void lookups; receivers allow 2/.test(i)));
  assert.ok(issues.some((i) => /gone1\.example, which has no SPF record \(void lookup\)/.test(i)));
  assert.ok(issues.some((i) => /dup\.example\.com publishes more than one SPF record/.test(i)));
});

test('include loops are reported, not followed forever', async () => {
  const zone = { 'a.example': ['v=spf1 include:b.example -all'], 'b.example': ['v=spf1 include:a.example -all'] };
  const a = await analyzeSpf('example.com', dnsFrom(zone), 'v=spf1 include:a.example -all');
  assert.ok(a.errors.some((e) => /loop: example\.com → a\.example → b\.example → a\.example/.test(e)));
});

test('redirect= is followed, but ignored when the record has "all"', async () => {
  const zone = { '_spf.example.net': ['v=spf1 include:x.example.net mx -all'], 'x.example.net': ['v=spf1 a -all'] };
  const a = await analyzeSpf('example.com', dnsFrom(zone), 'v=spf1 redirect=_spf.example.net');
  assert.equal(a.count, 4, 'redirect 1 + include 1 + a 1 + mx 1');
  const b = await analyzeSpf('example.com', dnsFrom(zone), 'v=spf1 -all redirect=_spf.example.net');
  assert.equal(b.count, 0);
});

test('a huge include tree stops at our query budget instead of hammering DNS', async () => {
  let queries = 0;
  const resolve = async (name) => { queries++; return [[`v=spf1 include:${name}x include:${name}y -all`]]; };
  const a = await analyzeSpf('example.com', resolve, 'v=spf1 include:t -all');
  assert.ok(queries <= 40, `${queries} queries`);
  assert.equal(a.truncated, true);
  assert.ok(spfLookupIssues(a).some((i) => /stopped counting early/.test(i)));
});

test('parseTerms strips qualifiers and splits name and value', () => {
  assert.deepEqual(parseTerms('v=spf1 -include:x.com ~all redirect=y.com a/24').map((t) => [t.name, t.value, !!t.modifier]),
    [['include', 'x.com', false], ['all', '', false], ['redirect', 'y.com', true], ['a', '', false]]);
});
