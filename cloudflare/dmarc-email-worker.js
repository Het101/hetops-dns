// Cloudflare Email Worker: forwards every DMARC report email to DNS Intelligence.
//
// Setup (Cloudflare dashboard):
//   1. Workers & Pages > Create > Worker, name it "dmarc-ingest", paste this file, Deploy.
//   2. Worker > Settings > Variables and Secrets > add a Secret named INGEST_SECRET
//      (the same long random value as DMARC_INGEST_SECRET in Coolify).
//   3. hetops.dev > Email > Email Routing > Routing rules > Catch-all address:
//      Action "Send to a Worker", destination "dmarc-ingest".
export default {
  async email(message, env) {
    if (message.rawSize > 10 * 1024 * 1024) {
      message.setReject('Message too large');
      return;
    }
    const raw = await new Response(message.raw).arrayBuffer();
    const res = await fetch(env.INGEST_URL || 'https://dns.hetops.dev/api/dmarc/ingest', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.INGEST_SECRET}`,
        'X-Envelope-To': message.to,
        'Content-Type': 'message/rfc822',
      },
      body: raw,
    });
    // A thrown error makes Cloudflare report a temporary failure, so the sender retries later.
    if (res.status !== 202) throw new Error(`ingest returned ${res.status}`);
  },
};
