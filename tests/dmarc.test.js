const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { parseReport, readReportFile, summarize } = require('../public/shared/dmarc');

const fx = (f) => fs.readFileSync(path.join(__dirname, 'fixtures', f));

test('parseReport reads metadata, policy and every record', () => {
  const r = parseReport(fx('dmarc-sample.xml').toString('utf8'));
  assert.equal(r.org, 'google.com');
  assert.equal(r.domain, 'example.com');
  assert.equal(r.policy.p, 'quarantine');
  assert.equal(r.begin, 1759449600);
  assert.equal(r.records.length, 3);
  assert.deepEqual(r.records[1], {
    ip: '167.89.0.10', count: 45, disposition: 'none', dkim: 'fail', spf: 'pass', headerFrom: 'example.com',
    authDkim: [{ domain: 'sendgrid.net', result: 'pass', selector: 's1' }],
    authSpf: [{ domain: 'example.com', result: 'pass' }],
  });
});

test('xml, gzip and zip files all read to the same report', async () => {
  const xml = await readReportFile(fx('dmarc-sample.xml'), 'r.xml');
  assert.equal(await readReportFile(fx('dmarc-sample.xml.gz'), 'r.xml.gz'), xml);
  assert.equal(await readReportFile(fx('dmarc-sample.zip'), 'r.zip'), xml);
  await assert.rejects(readReportFile(Buffer.from('not a report'), 'x.pdf'), /not a DMARC report/);
});

test('summarize finds senders, pass rate, spoofing and misaligned DKIM', () => {
  const s = summarize([parseReport(fx('dmarc-sample.xml').toString('utf8'))]);
  assert.equal(s.messages, 172);
  assert.equal(s.passed, 165);
  assert.equal(s.failed, 7);
  assert.equal(s.passRate, 95.9);

  const bySender = Object.fromEntries(s.senders.map((x) => [x.label, x]));
  assert.equal(bySender['Google Workspace'].count, 120);
  assert.equal(bySender['SendGrid'].passed, 45);
  assert.equal(bySender['203.0.113.66'].failed, 7);

  const text = s.issues.map((i) => i.text).join('\n');
  assert.match(text, /7 messages from 203\.0\.113\.66 failed both SPF and DKIM/);
  assert.match(text, /SendGrid signs with sendgrid\.net/);
  assert.equal(s.issues[0].sev, 'err', 'worst issue first');
});

test('summarize merges several reports and warns on p=none', () => {
  const r = parseReport(fx('dmarc-sample.xml').toString('utf8'));
  const none = { ...r, reportId: 'next-day', policy: { ...r.policy, p: 'none' } };
  const s = summarize([r, none]);
  assert.equal(s.messages, 344);
  assert.equal(s.reports, 2);
  assert.match(s.issues.map((i) => i.text).join('\n'), /p=none/);
});

test('the same report loaded twice is counted once', () => {
  const r = parseReport(fx('dmarc-sample.xml').toString('utf8'));
  const s = summarize([r, { ...r }]);
  assert.equal(s.reports, 1);
  assert.equal(s.messages, 172);
});
