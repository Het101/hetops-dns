/**
 * HetOps DNS — DMARC aggregate (rua) report reader.
 *
 * Reads the XML reports mailbox providers send (RFC 7489, appendix C), as .xml, .gz or .zip,
 * and turns them into "who sends as you, what passes, what to fix".
 * Runs in the browser (window.HetOpsDmarc; files never leave the device) and in Node (require),
 * so automatic ingestion can reuse the same parser later.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.HetOpsDmarc = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  // ── Reading files ──────────────────────────────────────────────
  function u8(b) { return b instanceof Uint8Array ? b : new Uint8Array(b); }
  async function inflate(bytes, format) {
    var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }
  // Minimal zip reader: first .xml entry via the central directory (stored or deflate).
  // ponytail: single-file report zips only, which is what every provider sends.
  async function unzipFirstXml(b) {
    var dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    var eocd = -1;
    for (var i = b.length - 22; i >= Math.max(0, b.length - 65557); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) throw new Error('Damaged zip file');
    var count = dv.getUint16(eocd + 10, true), p = dv.getUint32(eocd + 16, true);
    for (var n = 0; n < count; n++) {
      if (dv.getUint32(p, true) !== 0x02014b50) break;
      var method = dv.getUint16(p + 10, true), size = dv.getUint32(p + 20, true);
      var nameLen = dv.getUint16(p + 28, true), extra = dv.getUint16(p + 30, true), comment = dv.getUint16(p + 32, true);
      var local = dv.getUint32(p + 42, true);
      var name = new TextDecoder().decode(b.subarray(p + 46, p + 46 + nameLen));
      if (/\.xml$/i.test(name)) {
        var start = local + 30 + dv.getUint16(local + 26, true) + dv.getUint16(local + 28, true);
        var data = b.subarray(start, start + size);
        return method === 0 ? data : await inflate(data, 'deflate-raw');
      }
      p += 46 + nameLen + extra + comment;
    }
    throw new Error('No XML report inside the zip');
  }
  async function readReportFile(bytes, name) {
    var b = u8(bytes), out = b;
    if (b[0] === 0x1f && b[1] === 0x8b) out = await inflate(b, 'gzip');
    else if (b[0] === 0x50 && b[1] === 0x4b) out = await unzipFirstXml(b);
    var text = new TextDecoder().decode(out).replace(/^﻿/, '');
    if (!/<feedback[\s>]/.test(text)) throw new Error((name || 'File') + ' is not a DMARC report');
    return text;
  }

  // ── Parsing (fixed schema, so targeted extraction beats a full XML parser) ─
  function tag(xml, t) { var m = xml.match(new RegExp('<' + t + '>\\s*([\\s\\S]*?)\\s*</' + t + '>')); return m ? m[1].trim() : ''; }
  function all(xml, t) { return xml.match(new RegExp('<' + t + '>[\\s\\S]*?</' + t + '>', 'g')) || []; }
  function parseReport(xml) {
    var meta = tag(xml, 'report_metadata'), pol = tag(xml, 'policy_published'), range = tag(meta, 'date_range');
    return {
      org: tag(meta, 'org_name'),
      reportId: tag(meta, 'report_id'),
      begin: +tag(range, 'begin') || 0,
      end: +tag(range, 'end') || 0,
      domain: tag(pol, 'domain').toLowerCase(),
      policy: { p: tag(pol, 'p') || 'none', sp: tag(pol, 'sp'), pct: +tag(pol, 'pct') || 100, adkim: tag(pol, 'adkim') || 'r', aspf: tag(pol, 'aspf') || 'r' },
      records: all(xml, 'record').map(function (rec) {
        var row = tag(rec, 'row'), ev = tag(row, 'policy_evaluated'), auth = tag(rec, 'auth_results');
        return {
          ip: tag(row, 'source_ip'),
          count: +tag(row, 'count') || 0,
          disposition: tag(ev, 'disposition') || 'none',
          dkim: tag(ev, 'dkim') || 'fail',
          spf: tag(ev, 'spf') || 'fail',
          headerFrom: tag(tag(rec, 'identifiers'), 'header_from').toLowerCase(),
          authDkim: all(auth, 'dkim').map(function (d) {
            return { domain: tag(d, 'domain').toLowerCase(), result: tag(d, 'result'), selector: tag(d, 'selector') };
          }),
          authSpf: all(auth, 'spf').map(function (s) { return { domain: tag(s, 'domain').toLowerCase(), result: tag(s, 'result') }; }),
        };
      }),
    };
  }

  // ── Summary ────────────────────────────────────────────────────
  var KNOWN = [
    [/(^|\.)google(mail)?\.com$|\._domainkey\.google/, 'Google'],
    [/(^|\.)(outlook|hotmail|office365)\.com$|protection\.outlook\.com$|onmicrosoft\.com$/, 'Microsoft 365'],
    [/(^|\.)sendgrid\.(net|com)$/, 'SendGrid'],
    [/(^|\.)amazonses\.com$/, 'Amazon SES'],
    [/(^|\.)mailgun\.(org|net)$/, 'Mailgun'],
    [/(^|\.)(mcsv\.net|mailchimp\.com|mandrillapp\.com|rsgsv\.net)$/, 'Mailchimp'],
    [/(^|\.)zendesk\.com$/, 'Zendesk'],
    [/(^|\.)(salesforce|exacttarget)\.com$/, 'Salesforce'],
    [/(^|\.)postmarkapp\.com$|(^|\.)mtasv\.net$/, 'Postmark'],
    [/(^|\.)hubspot(email)?\.(com|net)$/, 'HubSpot'],
    [/(^|\.)zoho\.(com|eu|in)$/, 'Zoho Mail'],
  ];
  var SELECTOR_HINT = { google: 'Google Workspace', selector1: 'Microsoft 365', selector2: 'Microsoft 365', zmail: 'Zoho Mail' };
  function known(domain) { for (var i = 0; i < KNOWN.length; i++) if (KNOWN[i][0].test(domain)) return KNOWN[i][1]; return ''; }
  // Relaxed alignment by organisational domain. ponytail: last two labels, no public-suffix list (co.uk-style edge case).
  function org(d) { return String(d || '').split('.').slice(-2).join('.'); }

  function senderOf(r) {
    var d = r.authDkim.filter(function (x) { return x.result === 'pass'; })[0];
    if (d) {
      var label = known(d.domain) || (org(d.domain) === org(r.headerFrom) && SELECTOR_HINT[d.selector]) || d.domain;
      return { key: 'dkim:' + d.domain + ':' + (d.selector || ''), label: label };
    }
    var s = r.authSpf.filter(function (x) { return x.result === 'pass'; })[0];
    if (s) return { key: 'spf:' + s.domain, label: known(s.domain) || s.domain };
    return { key: 'ip:' + r.ip, label: r.ip };
  }

  function summarize(reports) {
    // The same report is often saved or dropped twice; count each (org, report id) once.
    var seen = {};
    reports = reports.filter(function (r) {
      var k = r.org + '|' + r.reportId;
      if (r.reportId && seen[k]) return false;
      seen[k] = true; return true;
    });
    var senders = {}, messages = 0, passed = 0, issues = [], policies = {}, domains = {};
    reports.forEach(function (rep) {
      policies[rep.policy.p] = true; if (rep.domain) domains[rep.domain] = true;
      rep.records.forEach(function (r) {
        var ok = r.dkim === 'pass' || r.spf === 'pass';
        messages += r.count; if (ok) passed += r.count;
        var who = senderOf(r);
        var s = senders[who.key] || (senders[who.key] = { label: who.label, ips: [], count: 0, passed: 0, failed: 0, dkimAligned: 0, spfAligned: 0, misalignedDkim: '' });
        if (s.ips.indexOf(r.ip) === -1) s.ips.push(r.ip);
        s.count += r.count; if (ok) s.passed += r.count; else s.failed += r.count;
        if (r.dkim === 'pass') s.dkimAligned += r.count;
        if (r.spf === 'pass') s.spfAligned += r.count;
        var foreign = r.authDkim.filter(function (x) { return x.result === 'pass' && org(x.domain) !== org(r.headerFrom); })[0];
        if (r.dkim !== 'pass' && foreign) s.misalignedDkim = foreign.domain;
      });
    });
    var list = Object.keys(senders).map(function (k) { return senders[k]; }).sort(function (a, b) { return b.count - a.count; });

    list.forEach(function (s) {
      if (s.failed && !s.passed)
        issues.push({ sev: 'err', text: s.failed + ' messages from ' + s.ips.join(', ') + ' failed both SPF and DKIM. If you do not recognise this sender, someone may be spoofing your domain.' });
      if (s.misalignedDkim)
        issues.push({ sev: 'warn', text: s.label + ' signs with ' + s.misalignedDkim + ', not your domain, so DKIM is not aligned. Turn on custom DKIM for your domain in ' + s.label + '.' });
      else if (s.passed && !s.dkimAligned)
        issues.push({ sev: 'warn', text: s.label + ' passes only on SPF. SPF breaks when mail is forwarded; add DKIM signing in ' + s.label + '.' });
    });
    if (policies.none) issues.push({ sev: 'warn', text: 'Your DMARC policy is p=none: failing mail is still delivered. Once every real sender passes, move to p=quarantine.' });
    var rank = { err: 0, warn: 1, info: 2 };
    issues.sort(function (a, b) { return rank[a.sev] - rank[b.sev]; });

    return {
      reports: reports.length, domains: Object.keys(domains), messages: messages, passed: passed, failed: messages - passed,
      passRate: messages ? Math.round((passed / messages) * 1000) / 10 : 0,
      senders: list, issues: issues,
      begin: Math.min.apply(null, reports.map(function (r) { return r.begin; }).concat([Infinity])),
      end: Math.max.apply(null, reports.map(function (r) { return r.end; }).concat([0])),
    };
  }

  return { readReportFile: readReportFile, parseReport: parseReport, summarize: summarize };
});
