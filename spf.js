// SPF DNS-lookup accounting, as receivers do it (RFC 7208 section 4.6.4).
//
// Receivers allow at most 10 DNS-querying terms while evaluating SPF, counted
// across every nested include: and redirect=, and at most 2 "void" lookups
// (a name that answers with nothing). Past either limit the result is
// permerror, which DMARC treats as an SPF fail. Counting only the top-level
// record misses almost every real overrun, because the cost hides inside
// includes such as _spf.google.com (which pulls in three more).
//
// resolveTxt(name) must behave like dns.promises.resolveTxt: resolve to an
// array of string arrays, or reject (ENOTFOUND / ENODATA count as void).

const LIMIT = 10;
const VOID_LIMIT = 2;
// Our own budget, so one scan can't make us query an unbounded include tree.
const MAX_QUERIES = 40;

const DNS_TERM = /^(include|a|mx|ptr|exists)$/;

function parseTerms(record) {
  return record.trim().split(/\s+/).slice(1).map((raw) => {
    const t = raw.replace(/^[+\-~?]/, '');
    const m = t.match(/^([a-z][a-z0-9_.-]*)(?:([:=/])(.*))?$/i);
    if (!m) return { raw, name: '', value: '' };
    const sep = m[2] || '';
    return { raw, name: m[1].toLowerCase(), modifier: sep === '=', value: sep === '/' ? '' : (m[3] || '') };
  });
}

async function analyzeSpf(domain, resolveTxt, rootRecord) {
  const out = { count: 0, voidCount: 0, breakdown: [], errors: [], truncated: false };
  let queries = 0;

  async function fetchSpf(name) {
    if (queries >= MAX_QUERIES) { out.truncated = true; return { records: [], stopped: true }; }
    queries++;
    try {
      const txt = await resolveTxt(name);
      return { records: txt.map((r) => r.join('')).filter((r) => /^v=spf1(\s|$)/i.test(r)) };
    } catch (e) {
      if (e && (e.code === 'ENOTFOUND' || e.code === 'ENODATA')) return { records: [], void: true };
      return { records: [], failed: e && e.code };
    }
  }

  // Cost of evaluating `record` (published at `name`), including everything it pulls in.
  async function walk(name, record, path) {
    let cost = 0;
    const terms = parseTerms(record);
    const hasAll = terms.some((t) => t.name === 'all' && !t.modifier);
    for (const t of terms) {
      const isRedirect = t.modifier && t.name === 'redirect';
      if (!(DNS_TERM.test(t.name) && !t.modifier) && !isRedirect) continue;
      if (isRedirect && hasAll) continue;                 // redirect is ignored when "all" is present
      cost++;
      if (t.name !== 'include' && !isRedirect) continue;  // a, mx, ptr, exists: one lookup, no nesting
      const target = t.value.toLowerCase().replace(/\.$/, '');
      if (!target || target.includes('%')) continue;      // macros can't be expanded without a sender
      if (path.includes(target)) { out.errors.push(`SPF include loop: ${[...path, target].join(' → ')}`); continue; }
      const res = await fetchSpf(target);
      if (res.stopped) continue;
      if (res.void) out.voidCount++;
      if (res.records.length !== 1) {
        out.errors.push(res.records.length > 1
          ? `${target} publishes more than one SPF record, which is a permerror`
          : `${t.raw} points at ${target}, which has no SPF record (${res.void ? 'void lookup' : 'lookup failed'})`);
        continue;
      }
      cost += await walk(target, res.records[0], [...path, target]);
    }
    return cost;
  }

  // Per top-level term, so the report can say which include is expensive.
  const terms = parseTerms(rootRecord);
  const hasAll = terms.some((t) => t.name === 'all' && !t.modifier);
  for (const t of terms) {
    const isRedirect = t.modifier && t.name === 'redirect';
    if (!(DNS_TERM.test(t.name) && !t.modifier) && !isRedirect) continue;
    if (isRedirect && hasAll) continue;
    const cost = await walk(domain, t.raw.replace(/^[+\-~?]/, '').replace(/^/, 'v=spf1 '), [domain]);
    out.breakdown.push({ term: t.raw, cost });
    out.count += cost;
  }
  out.breakdown.sort((a, b) => b.cost - a.cost);
  return out;
}

// Plain-language issues for the report.
function spfLookupIssues(a) {
  const issues = [...a.errors];
  if (a.count > LIMIT) {
    const top = a.breakdown.filter((b) => b.cost > 1).slice(0, 3).map((b) => `${b.term} (${b.cost})`).join(', ');
    issues.unshift(`SPF needs ${a.count} DNS lookups; receivers stop at ${LIMIT} and SPF fails (permerror)${top ? `. Biggest: ${top}` : ''}`);
  }
  if (a.voidCount > VOID_LIMIT) issues.push(`SPF has ${a.voidCount} void lookups; receivers allow ${VOID_LIMIT}, then SPF fails`);
  if (a.truncated) issues.push('SPF include tree is unusually large; stopped counting early');
  return issues;
}

module.exports = { analyzeSpf, spfLookupIssues, parseTerms, LIMIT };
