// Plans and Lemon Squeezy billing.
//
// Lemon Squeezy is the merchant of record: it runs checkout, takes payment and handles
// sales tax. We only (1) send people to its hosted checkout with their user id attached,
// and (2) trust its signed webhooks to tell us which plan an account is on.
//
// Env: LS_CHECKOUT_PRO / LS_CHECKOUT_TEAM  - the variants' "Share" checkout URLs
//      LS_VARIANT_PRO / LS_VARIANT_TEAM    - the variant ids (to map webhooks to plans)
//      LS_WEBHOOK_SECRET                   - the webhook signing secret
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

function planForVariant(variantId) {
  const v = String(variantId);
  if (v && v === String(process.env.LS_VARIANT_TEAM)) return 'team';
  if (v && v === String(process.env.LS_VARIANT_PRO)) return 'pro';
  return null;
}

// Webhook payload -> the billing fields to store, or null if it is not ours to act on.
function billingUpdate(payload) {
  const userId = Number(payload?.meta?.custom_data?.user_id);
  const a = payload?.data?.attributes;
  if (!userId || !a || !/^subscription_/.test(payload?.meta?.event_name || '')) return null;
  const plan = planForVariant(a.variant_id);
  if (!plan) return null;
  const ts = (d) => (d ? Date.parse(d) || null : null);
  return {
    userId,
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
