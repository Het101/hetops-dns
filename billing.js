// Plans and Lemon Squeezy billing.
//
// Lemon Squeezy is the merchant of record: it runs checkout, takes payment and handles
// sales tax. We only (1) send people to its hosted checkout with their user id attached,
// and (2) trust its signed webhooks to tell us which plan an account is on.
//
// Env: LS_CHECKOUT_PRO / LS_CHECKOUT_TEAM  - the variants' "Share" checkout URLs
//      LS_VARIANT_PRO / LS_VARIANT_TEAM    - optional variant ids; otherwise the variant name ("Pro", "Team") decides
//      LS_WEBHOOK_SECRET                   - the webhook signing secret
//      LS_PRODUCT_NAME                     - this app's product in the shared store (default "Domain Watch")
//      PLAN_OVERRIDES                      - "email:plan,email:plan" (e.g. the owner on team)
const crypto = require('crypto');

const PLANS = {
  free: { key: 'free', name: 'Free', price: 0, limits: { domains: 1, dmarcAuto: false, webhooks: false, digest: false, api: false } },
  pro: { key: 'pro', name: 'Pro', price: 5, limits: { domains: 10, dmarcAuto: true, webhooks: true, digest: false, api: false } },
  team: { key: 'team', name: 'Team', price: 19, limits: { domains: 50, dmarcAuto: true, webhooks: true, digest: true, api: true } },
};

function overrides() {
  const map = {};
  for (const part of String(process.env.PLAN_OVERRIDES || '').split(',')) {
    const [email, plan] = part.split(':').map((s) => (s || '').trim().toLowerCase());
    if (email && PLANS[plan]) map[email] = plan;
  }
  return map;
}

// The plan a user actually gets right now.
function planFor(user) {
  if (!user) return PLANS.free;
  const forced = overrides()[String(user.email || '').toLowerCase()];
  if (forced) return PLANS[forced];
  const plan = PLANS[user.plan];
  if (!plan) return PLANS.free;
  const status = user.plan_status;
  if (status === 'active' || status === 'on_trial' || status === 'past_due') return plan;   // past_due: card retries are under way
  if (status === 'cancelled' && user.plan_ends_at && user.plan_ends_at > Date.now()) return plan;  // paid until period end
  return PLANS.free;
}

function verifySignature(rawBody, signature) {
  const secret = process.env.LS_WEBHOOK_SECRET;
  if (!secret || !signature) return false;
  const want = Buffer.from(crypto.createHmac('sha256', secret).update(rawBody).digest('hex'));
  const got = Buffer.from(String(signature));
  return want.length === got.length && crypto.timingSafeEqual(want, got);
}

// Variant ids differ between test and live mode, so the variant name is the default key.
function planForVariant(variantId, variantName) {
  const v = variantId == null ? '' : String(variantId);
  if (v && v === process.env.LS_VARIANT_TEAM) return 'team';
  if (v && v === process.env.LS_VARIANT_PRO) return 'pro';
  const name = String(variantName || '').trim().toLowerCase();
  return name === 'pro' || name === 'team' ? name : null;
}

// Webhook payload -> the billing fields to store, or null if it is not ours to act on.
function billingUpdate(payload) {
  // Test-mode checkouts take Lemon Squeezy's fake cards, so a test-mode event must never change a
  // real account's plan. Only a deployment that opts in (local testing) accepts them.
  if (payload?.meta?.test_mode === true && process.env.LS_ALLOW_TEST_MODE !== 'true') return null;
  const a = payload?.data?.attributes;
  // Only subscription objects carry the plan. subscription_payment_* events send an invoice
  // (no variant, status "paid") and must not touch the plan.
  if (!a || payload?.data?.type !== 'subscriptions') return null;
  // One Lemon Squeezy store sells every HetOps product, and each webhook receives all of
  // their events: act only on this app's product.
  const product = (process.env.LS_PRODUCT_NAME || 'Domain Watch').trim().toLowerCase();
  if (a.product_name && String(a.product_name).trim().toLowerCase() !== product) return null;
  // Our checkout links carry the user id. A purchase made straight from the store page has
  // none, so it falls back to the buyer's email (verified by Lemon Squeezy, signed by them).
  const userId = Number(payload?.meta?.custom_data?.user_id) || null;
  const rawEmail = String(a.user_email || '').trim().toLowerCase();
  const email = /^[^\s@]{1,64}@[^\s@.]+(\.[^\s@.]+)+$/.test(rawEmail) && rawEmail.length <= 254 ? rawEmail : null;
  if (!userId && !email) return null;
  const plan = planForVariant(a.variant_id, a.variant_name);
  if (!plan) return null;
  const ts = (d) => (d ? Date.parse(d) || null : null);
  return {
    userId, email,
    plan,
    status: a.status,
    endsAt: ts(a.ends_at) || ts(a.renews_at),
    customerId: a.customer_id != null ? String(a.customer_id) : null,
    subscriptionId: payload.data.id != null ? String(payload.data.id) : null,
    portalUrl: a.urls?.customer_portal || null,
  };
}

function checkoutUrl(plan, user) {
  const base = plan === 'pro' ? process.env.LS_CHECKOUT_PRO : plan === 'team' ? process.env.LS_CHECKOUT_TEAM : null;
  if (!base || !user) return null;
  const url = new URL(base);
  url.searchParams.set('checkout[email]', user.email);
  url.searchParams.set('checkout[custom][user_id]', String(user.id));
  return url.toString();
}

module.exports = { PLANS, planFor, verifySignature, billingUpdate, checkoutUrl };
