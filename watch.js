// Service watch: a fixed list of HetOps endpoints, checked from the server at most once a
// minute and served to the portfolio's eye. The list is code, never request input, so
// there is nothing for a caller to point elsewhere.
const TARGETS = [
  { name: 'hetops.dev', url: 'https://hetops.dev/' },
  { name: 'DNS Intelligence', url: null }, // this process: answering the request proves it is up
  { name: 'Dev Toolkit', url: 'https://tools.hetops.dev/' },
  { name: 'Status', url: 'https://status.hetops.dev/' },
  { name: 'Analytics', url: 'https://analytics.hetops.dev/' },
];

function createWatch({ targets = TARGETS, fetchImpl = fetch, ttlMs = 60_000, timeoutMs = 5000, now = Date.now } = {}) {
  let cached = null, inflight = null;

  async function probe(t) {
    if (!t.url) return { name: t.name, up: true, ms: 0 };
    const started = now();
    try {
      const res = await fetchImpl(t.url, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
      // Anything that is not a server error counts as up; a redirect to a login page is fine.
      return { name: t.name, up: res.status < 500, ms: now() - started };
    } catch {
      return { name: t.name, up: false, ms: now() - started };
    }
  }

  return async function status() {
    if (cached && now() - cached.at < ttlMs) return cached.body;
    if (!inflight) {
      inflight = Promise.all(targets.map(probe)).then((services) => {
        const body = { checkedAt: new Date(now()).toISOString(), up: services.filter((s) => s.up).length, total: services.length, services };
        cached = { at: now(), body };
        return body;
      }).finally(() => { inflight = null; });
    }
    return inflight;
  };
}

module.exports = { createWatch, TARGETS };
