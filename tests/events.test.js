const { test } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');

// Own throwaway database; each test file runs in its own process.
process.env.DB_PATH = path.join(os.tmpdir(), `hetops-events-${process.pid}.db`);
const store = require('../db');

test('alert events are stored per user, newest first, and trimmed', () => {
  const a = store.upsertUser('a@example.com');
  const b = store.upsertUser('b@example.com');

  store.addAlertEvents(a.id, 'example.com', ['SPF record changed: x → y', 'MX records changed: a → b']);
  store.addAlertEvents(b.id, 'other.com', ['Nameservers changed: n1 → n2']);

  const evA = store.listAlertEvents(a.id);
  assert.equal(evA.length, 2);
  assert.ok(evA.every((e) => e.domain === 'example.com' && typeof e.ts === 'number'));
  assert.deepEqual(store.listAlertEvents(b.id).map((e) => e.change), ['Nameservers changed: n1 → n2']);

  // Newest first.
  store.addAlertEvents(a.id, 'example.com', ['DMARC policy weakened: reject → none']);
  assert.equal(store.listAlertEvents(a.id)[0].change, 'DMARC policy weakened: reject → none');

  // Bounded history: never more than the cap per user.
  store.addAlertEvents(a.id, 'example.com', Array.from({ length: 600 }, (_, i) => `change ${i}`));
  assert.equal(store.listAlertEvents(a.id, 1000).length, store.ALERT_EVENT_CAP);

  // Empty input is a no-op.
  store.addAlertEvents(b.id, 'other.com', []);
  assert.equal(store.listAlertEvents(b.id).length, 1);
});
