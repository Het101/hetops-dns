// Turns an inbound DMARC report email into parsed reports.
// Email from strangers is untrusted input: postal-mime does the MIME parsing, and only
// .xml / .gz / .zip attachments that parse as DMARC aggregate reports are kept.
const PostalMime = require('postal-mime').default || require('postal-mime');
const { readReportFile, parseReport } = require('./public/shared/dmarc');

const MAX_ATTACHMENTS = 10;

async function extractReports(raw) {
  const email = await PostalMime.parse(raw);
  const reports = [], errors = [];
  for (const a of (email.attachments || []).slice(0, MAX_ATTACHMENTS)) {
    const name = a.filename || '';
    if (!/\.(xml|gz|zip)$/i.test(name) && !/(xml|gzip|zip)/i.test(a.mimeType || '')) continue;
    try {
      reports.push(parseReport(await readReportFile(new Uint8Array(a.content), name)));
    } catch (e) { errors.push(`${name}: ${e.message}`); }
  }
  return { reports, errors, to: (email.to || []).map((t) => t.address) };
}

// Our addresses look like dmarc-<16+ hex>@hetops.dev; anything else is not ours.
function tokenFromAddress(addr) {
  const m = String(addr || '').toLowerCase().match(/^dmarc-([0-9a-f]{16,64})@/);
  return m ? m[1] : null;
}

module.exports = { extractReports, tokenFromAddress };
