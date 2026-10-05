const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createWatch } = require('../watch');

const targets = [
  { name: 'self', url: null },
  { name: 'ok', url: 'https://ok.example/' },
  { name: 'login', url: 'https://login.example/' },
  { name: 'broken', url: 'https://broken.example/' },
  { name: 'gone', url: 'https://gone.example/' },
];
const fakeFetch = (calls) => async (url) => {
  calls.push(url);
  if (url.includes('gone')) throw new Error('ECONNREFUSED');
  return { status: url.includes('broken') ? 502 : url.includes('login') ? 302 : 200 };
};

test('reports each service: 2xx and redirects are up, 5xx and network errors are down', async () => {
  const calls = [];
  const body = await createWatch({ targets, fetchImpl: fakeFetch(calls) })();
  const up = Object.fromEntries(body.services.map((s) => [s.name, s.up]));
  assert.deepEqual(up, { self: true, ok: true, login: true, broken: false, gone: false });
  assert.equal(body.up, 3); assert.equal(body.total, 5);
  assert.equal(calls.length, 4, 'the self entry is never fetched');
});

test('caches for the ttl and shares one probe between concurrent callers', async () => {
  const calls = []; let t = 0;
  const status = createWatch({ targets, fetchImpl: fakeFetch(calls), ttlMs: 60_000, now: () => t });
  await Promise.all([status(), status(), status()]);
  assert.equal(calls.length, 4);
  t = 30_000; await status();
  assert.equal(calls.length, 4, 'still cached inside the ttl');
  t = 61_000; await status();
  assert.equal(calls.length, 8, 'probed again after the ttl');
});
