const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const os = require('node:os');
const path = require('node:path');

process.env.DB_PATH = path.join(os.tmpdir(), `hetops-billing-${process.pid}-${Date.now()}.db`);
process.env.LS_WEBHOOK_SECRET = 'whsec-test-0123456789';
process.env.LS_VARIANT_PRO = '111';
process.env.LS_VARIANT_TEAM = '222';
process.env.LS_CHECKOUT_PRO = 'https://hetops.lemonsqueezy.com/buy/pro-uuid';
process.env.PLAN_OVERRIDES = 'owner@example.com:team';
const billing = require('../billing');
const store = require('../db');
const { app } = require('../server');

const DAY = 86400000;

test('planFor: free by default, paid while active or until a cancelled period ends, overrides win', () => {
  const now = Date.now();
  assert.equal(billing.planFor({ email: 'a@x.com' }).key, 'free');
  assert.equal(billing.planFor({ email: 'a@x.com', plan: 'pro', plan_status: 'active' }).key, 'pro');
  assert.equal(billing.planFor({ email: 'a@x.com', plan: 'pro', plan_status: 'past_due' }).key, 'pro', 'grace while card retries');
  assert.equal(billing.planFor({ email: 'a@x.com', plan: 'pro', plan_status: 'cancelled', plan_ends_at: now + DAY }).key, 'pro');
  assert.equal(billing.planFor({ email: 'a@x.com', plan: 'pro', plan_status: 'cancelled', plan_ends_at: now - DAY }).key, 'free');
  assert.equal(billing.planFor({ email: 'a@x.com', plan: 'team', plan_status: 'expired' }).key, 'free');
  assert.equal(billing.planFor({ email: 'Owner@Example.com' }).key, 'team');
  assert.deepEqual(billing.PLANS.pro.limits, { domains: 10, dmarcAuto: true, webhooks: true, digest: false, api: false });
});

test('verifySignature: HMAC-SHA256 of the raw body, constant-time', () => {
  const body = Buffer.from('{"a":1}');
  const sig = crypto.createHmac('sha256', process.env.LS_WEBHOOK_SECRET).update(body).digest('hex');
  assert.equal(billing.verifySignature(body, sig), true);
  assert.equal(billing.verifySignature(body, sig.replace(/.$/, '0')), false);
  assert.equal(billing.verifySignature(body, ''), false);
  assert.equal(billing.verifySignature(Buffer.from('{"a":2}'), sig), false);
});

test('checkoutUrl pre-fills email and carries the user id', () => {
  const url = new URL(billing.checkoutUrl('pro', { id: 42, email: 'me@x.com' }));
  assert.equal(url.origin + url.pathname, 'https://hetops.lemonsqueezy.com/buy/pro-uuid');
  assert.equal(url.searchParams.get('checkout[email]'), 'me@x.com');
  assert.equal(url.searchParams.get('checkout[custom][user_id]'), '42');
  assert.equal(billing.checkoutUrl('team', { id: 1, email: 'x' }), null, 'unconfigured plan has no checkout');
});

let server, base;
before(async () => { await new Promise((r) => { server = app.listen(0, '127.0.0.1', r); }); base = `http://127.0.0.1:${server.address().port}`; });
after(() => new Promise((r) => server.close(r)));

const hook = (payload, secret = process.env.LS_WEBHOOK_SECRET) => {
  const body = JSON.stringify(payload);
  return fetch(`${base}/api/billing/webhook`, {
    method: 'POST', body,
    headers: { 'Content-Type': 'application/json', 'X-Signature': crypto.createHmac('sha256', secret).update(body).digest('hex') },
  });
};
const sub = (userId, variant, status, extra = {}) => ({
  meta: { event_name: 'subscription_updated', custom_data: { user_id: String(userId) } },
  data: { type: 'subscriptions', id: 'sub_1', attributes: { status, variant_id: variant, customer_id: 9, renews_at: null, ends_at: null,
    urls: { customer_portal: 'https://hetops.lemonsqueezy.com/billing' }, ...extra } },
});

test('webhook: bad signature rejected; a valid subscription upgrades the user', async () => {
  const u = store.upsertUser('buyer@example.com');
  assert.equal((await hook(sub(u.id, 111, 'active'), 'wrong-secret')).status, 401);
  assert.equal(billing.planFor(store.getUser(u.id)).key, 'free');

  assert.equal((await hook(sub(u.id, 111, 'active'))).status, 200);
  const after1 = store.getUser(u.id);
  assert.equal(billing.planFor(after1).key, 'pro');
  assert.equal(after1.ls_portal_url, 'https://hetops.lemonsqueezy.com/billing');

  await hook(sub(u.id, 222, 'active'));
  assert.equal(billing.planFor(store.getUser(u.id)).key, 'team', 'plan change follows the variant');

  await hook(sub(u.id, 999, 'active', { variant_name: 'Pro' }));
  assert.equal(billing.planFor(store.getUser(u.id)).key, 'pro', 'unknown id falls back to the variant name');
  await hook(sub(u.id, 998, 'active', { variant_name: 'Team' }));
  assert.equal(billing.planFor(store.getUser(u.id)).key, 'team');

  // A renewal invoice must not change the plan, even with no variant ids configured.
  const ids = [process.env.LS_VARIANT_PRO, process.env.LS_VARIANT_TEAM];
  delete process.env.LS_VARIANT_PRO; delete process.env.LS_VARIANT_TEAM;
  assert.equal((await hook({ meta: { event_name: 'subscription_payment_success', custom_data: { user_id: String(u.id) } },
    data: { type: 'subscription-invoices', id: 'inv_1', attributes: { status: 'paid', subscription_id: 1 } } })).status, 200);
  assert.equal(billing.planFor(store.getUser(u.id)).key, 'team', 'invoice ignored');
  assert.equal(billing.billingUpdate(sub(u.id, undefined, 'active')), null, 'no id and no name maps to nothing');
  [process.env.LS_VARIANT_PRO, process.env.LS_VARIANT_TEAM] = ids;

  await hook(sub(u.id, 222, 'expired'));
  assert.equal(billing.planFor(store.getUser(u.id)).key, 'free');
});

test('plan limits: free watches 1 domain and gets an upgrade prompt; paid features answer 402', async () => {
  const u = store.upsertUser('limits@example.com');
  const cookie = `sid=${store.createSession(u.id)}`;
  const call = (method, p, body) => fetch(`${base}${p}`, {
    method, headers: { 'Content-Type': 'application/json', Cookie: cookie }, body: body && JSON.stringify(body) });

  assert.equal((await call('POST', '/api/alerts', { domain: 'one.example' })).status, 200);
  const second = await call('POST', '/api/alerts', { domain: 'two.example' });
  assert.equal(second.status, 402);
  assert.deepEqual(await second.json(), { error: 'The Free plan watches up to 1 domain.', upgrade: true });

  assert.equal((await call('POST', '/api/keys', { label: 'x' })).status, 402);
  assert.equal((await call('POST', '/api/settings', { digestEnabled: true })).status, 402);
  assert.equal((await call('POST', '/api/settings', { webhookUrl: 'https://hooks.slack.com/services/x' })).status, 402);

  const me = await (await call('GET', '/api/auth/me')).json();
  assert.equal(me.plan, 'free');
  assert.equal(me.limits.domains, 1);
});
