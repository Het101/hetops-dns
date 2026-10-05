/**
 * HetOps DNS — copy-paste fixes for missing security headers.
 *
 * Input is the `analysis.checks` map from /api/security-headers. Output is the list of
 * headers to add and remove, plus ready-to-paste config for common servers and hosts.
 * Shared by the browser (window.HetOpsFix) and the tests (require).
 *
 * Values are deliberately conservative so pasting them cannot break a site:
 * HSTS without `preload` (preloading is hard to undo), and a CSP that only locks
 * framing, plugins and <base> — script-src stays the site's own decision.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.HetOpsFix = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  var RECOMMENDED = [
    { name: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains',
      why: 'Browsers only ever connect over HTTPS for a year. Add "; preload" later, once every subdomain serves HTTPS.' },
    { name: 'Content-Security-Policy', value: "frame-ancestors 'self'; object-src 'none'; base-uri 'self'",
      why: 'A safe starting policy that blocks clickjacking, plugins and <base> hijacking. Tighten script-src next.' },
    { name: 'X-Content-Type-Options', value: 'nosniff',
      why: 'Stops browsers guessing file types, which can turn an upload into a script.' },
    { name: 'X-Frame-Options', value: 'SAMEORIGIN',
      why: 'Older browsers: stops other sites framing yours (clickjacking).' },
    { name: 'X-XSS-Protection', value: '0',
      why: 'Turns off the old XSS auditor, which itself caused leaks. Modern protection is CSP.' },
    { name: 'Referrer-Policy', value: 'strict-origin-when-cross-origin',
      why: 'Other sites see only your domain, never full URLs that may contain tokens.' },
    { name: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()',
      why: 'Blocks camera, microphone and location for your pages and anything embedded in them.' },
  ];
  // Present = a problem: they advertise software versions, or are deprecated.
  var REMOVE_IF_PRESENT = ['X-Powered-By', 'Server', 'Public-Key-Pins'];

  var PLATFORMS = [
    { id: 'nginx', label: 'Nginx', file: 'server { … } block' },
    { id: 'apache', label: 'Apache', file: '.htaccess or VirtualHost (mod_headers)' },
    { id: 'caddy', label: 'Caddy', file: 'Caddyfile site block' },
    { id: 'cloudflare', label: 'Cloudflare Pages / Netlify', file: '_headers file in your build output' },
    { id: 'vercel', label: 'Vercel', file: 'vercel.json' },
    { id: 'express', label: 'Node / Express', file: 'before your routes' },
  ];

  function buildHeaderFix(checks) {
    checks = checks || {};
    var add = RECOMMENDED.filter(function (h) { return checks[h.name] && !checks[h.name].passed; });
    var remove = REMOVE_IF_PRESENT.filter(function (n) { return checks[n] && checks[n].present; });
    return { add: add, remove: remove, empty: !add.length && !remove.length, snippets: snippets(add, remove) };
  }

  function snippets(add, remove) {
    var q = function (v) { return '"' + v.replace(/[\\"]/g, '\\$&') + '"'; };
    var hidesServer = remove.indexOf('Server') !== -1;
    var others = remove.filter(function (n) { return n !== 'Server'; });
    var out = {};

    out.nginx = add.map(function (h) { return 'add_header ' + h.name + ' ' + q(h.value) + ' always;'; })
      .concat(others.map(function (n) { return 'proxy_hide_header ' + n + ';'; }))
      .concat(hidesServer ? ['server_tokens off;  # hides the version; the name stays unless you use headers-more'] : [])
      .join('\n');

    out.apache = add.map(function (h) { return 'Header always set ' + h.name + ' ' + q(h.value); })
      .concat(others.map(function (n) { return 'Header always unset ' + n; }))
      .concat(hidesServer ? ['# In the main server config (not .htaccess):', 'ServerTokens Prod', 'ServerSignature Off'] : [])
      .join('\n');

    out.caddy = 'header {\n' + add.map(function (h) { return '  ' + h.name + ' ' + q(h.value); })
      .concat(remove.map(function (n) { return '  -' + n; })).join('\n') + '\n}';

    out.cloudflare = '/*\n' + add.map(function (h) { return '  ' + h.name + ': ' + h.value; })
      .concat(remove.length ? ['  # Response headers cannot be removed here: ' + remove.join(', ')] : []).join('\n');

    out.vercel = JSON.stringify({ headers: [{ source: '/(.*)', headers: add.map(function (h) { return { key: h.name, value: h.value }; }) }] }, null, 2);

    out.express = (remove.indexOf('X-Powered-By') !== -1 ? "app.disable('x-powered-by');\n" : '')
      + 'app.use((req, res, next) => {\n'
      + add.map(function (h) { return '  res.setHeader(' + JSON.stringify(h.name) + ', ' + JSON.stringify(h.value) + ');'; }).join('\n')
      + (remove.filter(function (n) { return n !== 'X-Powered-By'; }).length
        ? '\n' + remove.filter(function (n) { return n !== 'X-Powered-By'; }).map(function (n) { return '  res.removeHeader(' + JSON.stringify(n) + ');'; }).join('\n') : '')
      + '\n  next();\n});';
    return out;
  }

  return { buildHeaderFix: buildHeaderFix, PLATFORMS: PLATFORMS, RECOMMENDED: RECOMMENDED };
});
