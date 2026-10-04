const { test } = require('node:test');
const assert = require('node:assert/strict');
const { renderMagicLink, renderAlert, renderDigest } = require('../email');

test('sign-in email carries the link and the new brand', () => {
  const url = 'https://dns.hetops.dev/api/auth/verify?token=abc123';
  const html = renderMagicLink(url);
  assert.ok(html.includes(`href="${url}"`));
  assert.match(html, /hetops-mark\.png/);
  assert.match(html, />HetOps</);
  assert.ok(!html.includes('OPS_'), 'old wordmark is gone');
});

test('user-controlled values are escaped in every template', () => {
  const evil = '<img src=x onerror=alert(1)>.example.com';
  for (const html of [renderAlert(evil, [`SPF record changed: ${evil}`]), renderDigest([{ domain: evil, summary: evil }])]) {
    assert.ok(!html.includes('<img src=x'), 'raw HTML must not survive');
    assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
  }
});

test('alert colours follow severity; no em-dashes in any template', () => {
  const html = renderAlert('example.com', ['DMARC policy weakened: reject → none', 'Certificate now within 30 days of expiry (29d left)']);
  assert.match(html, /#f05252/);   // weakened = red
  assert.match(html, /#f59e0b/);   // expiry = amber
  for (const h of [html, renderMagicLink('https://x.test'), renderDigest([{ domain: 'a.com', summary: 'A, cert 40d' }])]) {
    assert.ok(!h.includes('—'), 'no em-dash');
  }
});
