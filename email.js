// ── Email delivery (nodemailer over SMTP) ──────────────────────
// Configure via environment variables:
//   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_SECURE (true/false), MAIL_FROM
// If SMTP_HOST is not set the module runs in "console mode": emails are logged to
// stdout instead of sent, so local development and CI work without a mail server.
const nodemailer = require('nodemailer');

const HOST = process.env.SMTP_HOST;
const FROM = process.env.MAIL_FROM || process.env.SMTP_USER || 'HetOps DNS <no-reply@hetops.dev>';
const APP_URL = process.env.APP_URL || 'https://dns.hetops.dev';
const enabled = !!HOST;

let transporter = null;
if (enabled) {
  transporter = nodemailer.createTransport({
    host: HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  });
}

// ── Template ───────────────────────────────────────────────────
// Email HTML is not web HTML: tables, inline styles and solid colours only (Outlook drops
// gradients, Gmail blocks SVG). The logo is a hosted PNG; everything else is live text.
const C = {
  page: '#0b0c0e', card: '#111316', line: '#24282d', text: '#ececed', muted: '#a1a1aa', faint: '#71717a',
  accent: '#0891b2', accentText: '#22b8d6', warn: '#f59e0b', err: '#f05252', brand: '#10b981',
};
const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace";

function shell({ preheader, title, body, footer }) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><meta name="supported-color-schemes" content="dark">
<title>${escapeHtml(title)}</title>
</head>
<body style="margin:0;padding:0;background:${C.page}">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:${C.page}">${escapeHtml(preheader)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${C.page}" style="background:${C.page}">
  <tr><td align="center" style="padding:32px 16px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:520px">
      <tr><td style="padding:0 4px 18px">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
          <td style="vertical-align:middle"><img src="${APP_URL}/email/hetops-mark.png" width="28" height="20" alt="" style="display:block;border:0"></td>
          <td style="vertical-align:middle;padding-left:10px;font:700 18px/1 ${FONT};letter-spacing:-0.4px;color:${C.text}">HetOps</td>
          <td style="vertical-align:middle;padding-left:10px">
            <span style="display:inline-block;font:600 11px/1 ${FONT};color:${C.accentText};border:1px solid ${C.accent};border-radius:999px;padding:4px 8px">DNS Intelligence</span>
          </td>
        </tr></table>
      </td></tr>
      <tr><td bgcolor="${C.card}" style="background:${C.card};border:1px solid ${C.line};border-radius:14px;padding:28px">
        <h1 style="margin:0 0 12px;font:600 20px/1.3 ${FONT};letter-spacing:-0.3px;color:${C.text}">${escapeHtml(title)}</h1>
        ${body}
      </td></tr>
      <tr><td style="padding:16px 4px 0;font:12px/1.6 ${FONT};color:${C.faint}">
        ${footer}<br>
        <a href="${APP_URL}" style="color:${C.faint};text-decoration:underline">dns.hetops.dev</a> &middot; part of <a href="https://hetops.dev" style="color:${C.faint};text-decoration:underline">HetOps</a>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`;
}

const p = (html) => `<p style="margin:0 0 16px;font:15px/1.6 ${FONT};color:${C.muted}">${html}</p>`;
function button(href, label) {
  return `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:8px 0 20px"><tr>
    <td bgcolor="${C.accent}" style="background:${C.accent};border-radius:10px">
      <a href="${href}" style="display:inline-block;padding:13px 24px;font:600 15px/1 ${FONT};color:#ffffff;text-decoration:none;border-radius:10px">${label}</a>
    </td></tr></table>`;
}
// Same severity wording as the in-app change timeline.
function tone(change) {
  if (/removed|weakened|expired|blacklisted|Nameservers changed|fail SPF/i.test(change)) return C.err;
  if (/within|expires in/i.test(change)) return C.warn;
  return C.accent;
}

async function send({ to, subject, html, text }) {
  if (!enabled) {
    console.log(`\n[email:console] To: ${to}\nSubject: ${subject}\n${text || '(html email)'}\n`);
    return { consoleMode: true };
  }
  return transporter.sendMail({ from: FROM, to, subject, html, text });
}

// ── Emails ─────────────────────────────────────────────────────
function renderMagicLink(url) {
  return shell({
    preheader: 'Your sign-in link for HetOps DNS. It works once and expires in 15 minutes.',
    title: 'Sign in to HetOps DNS',
    body: p('Use the button below to sign in. The link works once and expires in 15 minutes.')
      + button(url, 'Sign in')
      + `<p style="margin:0;font:13px/1.6 ${FONT};color:${C.faint}">Button not working? Copy this link into your browser:<br>
         <a href="${url}" style="color:${C.accentText};word-break:break-all;font-family:${MONO};font-size:12px">${escapeHtml(url)}</a></p>`,
    footer: 'You got this because someone asked to sign in to HetOps DNS with this address. If that wasn\'t you, ignore this email; nothing happens without the link.',
  });
}
function sendMagicLink(to, url) {
  return send({
    to, subject: 'Your HetOps DNS sign-in link', html: renderMagicLink(url),
    text: `Sign in to HetOps DNS\n\nOpen this link to sign in. It works once and expires in 15 minutes:\n${url}\n\nIf you didn't ask for this, ignore this email.`,
  });
}

function renderAlert(domain, changes) {
  const report = `${APP_URL}/?domain=${encodeURIComponent(domain)}`;
  const items = changes.map((c) => `
    <tr><td style="padding:0 0 8px">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
        <td width="3" bgcolor="${tone(c)}" style="background:${tone(c)};border-radius:2px"></td>
        <td style="padding:10px 14px;background:#16191d;border-radius:0 8px 8px 0;font:14px/1.5 ${FONT};color:${C.text}">${escapeHtml(c)}</td>
      </tr></table>
    </td></tr>`).join('');
  return shell({
    preheader: `${domain}: ${changes[0]}`,
    title: `${changes.length === 1 ? 'A change' : changes.length + ' changes'} on ${domain}`,
    body: p(`HetOps DNS monitoring spotted ${changes.length === 1 ? 'this change' : 'these changes'} on <b style="color:${C.text};font-family:${MONO}">${escapeHtml(domain)}</b>:`)
      + `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 12px">${items}</table>`
      + button(report, 'View the full report'),
    footer: 'You get these alerts because you watch this domain on HetOps DNS. Open Monitoring to stop watching it or turn off email.',
  });
}
function sendAlertEmail(to, domain, changes) {
  return send({
    to, subject: `${domain}: ${changes[0]}`, html: renderAlert(domain, changes),
    text: `Changes on ${domain}\n\n` + changes.map((c) => '- ' + c).join('\n') + `\n\nFull report: ${APP_URL}/?domain=${encodeURIComponent(domain)}`,
  });
}

// Weekly digest: one row per monitored domain with its current status.
function renderDigest(rows) {
  const body = rows.map((r) => `
    <tr>
      <td style="padding:12px 0;border-top:1px solid ${C.line};font:13px/1.4 ${MONO}">
        <a href="${APP_URL}/?domain=${encodeURIComponent(r.domain)}" style="color:${C.accentText};text-decoration:none">${escapeHtml(r.domain)}</a>
      </td>
      <td align="right" style="padding:12px 0 12px 12px;border-top:1px solid ${C.line};font:13px/1.4 ${FONT};color:${C.muted}">${escapeHtml(r.summary)}</td>
    </tr>`).join('');
  return shell({
    preheader: `Your ${rows.length} watched domain${rows.length !== 1 ? 's' : ''} this week.`,
    title: 'Your weekly domain report',
    body: p(`Where your ${rows.length} watched domain${rows.length !== 1 ? 's stand' : ' stands'} this week:`)
      + `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 20px">${body}</table>`
      + button(APP_URL, 'Open HetOps DNS'),
    footer: 'You get this weekly report because you turned it on in HetOps DNS. Turn it off under Monitoring, Alert delivery.',
  });
}
function sendDigest(to, rows) {
  return send({
    to, subject: `Weekly report: ${rows.length} domain${rows.length !== 1 ? 's' : ''}`, html: renderDigest(rows),
    text: 'Your weekly domain report\n\n' + rows.map((r) => `${r.domain}: ${r.summary}`).join('\n') + `\n\n${APP_URL}`,
  });
}

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

module.exports = { enabled, send, sendMagicLink, sendAlertEmail, sendDigest, renderMagicLink, renderAlert, renderDigest };
