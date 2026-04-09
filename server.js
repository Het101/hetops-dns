const express = require('express');
const dns = require('node:dns');
const { Resolver } = require('node:dns').promises;
const path = require('node:path');
const net = require('node:net');
const tls = require('node:tls');
const https = require('node:https');
const http = require('node:http');
const crypto = require('node:crypto');
const whois = require('whois');
const rateLimit = require('express-rate-limit');


function fetchIntermediateCerts(leafCert, timeout = 5000) {
  return new Promise((resolve) => {
    const intermediates = [];
    const visited = new Set();
    
    function certToObject(cert) {
      // Normalise subject/issuer: X509Certificate gives strings, getPeerCertificate gives objects.
      // Store the raw value so callers can handle both forms.
      const validFrom = cert.validFrom ?? cert.valid_from;
      const validTo   = cert.validTo   ?? cert.valid_to;
      return {
        subject: cert.subject,
        issuer:  cert.issuer,
        valid_from: validFrom,
        valid_to:   validTo,
        isCA: cert.ca ?? cert.isCA,          // X509Certificate uses .ca; old API uses .isCA
        fingerprint256: cert.fingerprint256,
        fingerprint:    cert.fingerprint,
        serialNumber:   cert.serialNumber,
        subjectaltname: cert.subjectAltName ?? cert.subjectaltname,
        signatureAlgorithm: cert.signatureAlgorithm,
        infoAccess: cert.infoAccess,         // needed so getAIAUrl works on recursive calls
        keyAlgorithm: cert.keyAlgorithm,
        bits: cert.bits,
        ocspURI: (() => {
          const ia = cert.infoAccess;
          if (!ia) return null;
          if (typeof ia === 'string') return ia.match(/OCSP[^:]*:\s*(https?:\/\/[^\n]+)/i)?.[1]?.trim() ?? null;
          if (typeof ia === 'object') {
            for (const key of Object.keys(ia)) {
              if (/OCSP/i.test(key)) {
                const v = Array.isArray(ia[key]) ? ia[key][0] : ia[key];
                if (typeof v === 'string' && v.startsWith('http')) return v.trim();
              }
            }
          }
          return null;
        })(),
        PEM: cert.PEM,
        raw: cert.raw,
      };
    }
    
    function getAIAUrl(certificate) {
      if (!certificate) return null;
      try {
        const infoAccess = certificate.infoAccess;
        if (infoAccess) {
          if (typeof infoAccess === 'string') {
            // Human-readable (getPeerCertificate): "CA Issuers - URI:http://..."
            let match = infoAccess.match(/CA Issuers[^:]*:\s*(?:URI:)?(https?:\/\/[^\n\s]+)/i);
            if (match) return match[1].trim();
            // OID format (X509Certificate.infoAccess): "1.3.6.1.5.5.7.48.2:\n  URI:http://..."
            match = infoAccess.match(/1\.3\.6\.1\.5\.5\.7\.48\.2[^\n]*\n\s*(?:URI:)?(https?:\/\/[^\n\s]+)/i);
            if (match) return match[1].trim();
          } else if (typeof infoAccess === 'object') {
            // Older Node.js object format: { 'CA Issuers - URI': 'http://...' }
            for (const key of Object.keys(infoAccess)) {
              if (/CA Issuers/i.test(key)) {
                const val = Array.isArray(infoAccess[key]) ? infoAccess[key][0] : infoAccess[key];
                if (typeof val === 'string' && val.startsWith('http')) return val.trim();
              }
            }
          }
        }
      } catch (e) {}
      return null;
    }
    
    async function fetchCert(url) {
      if (!url || visited.has(url) || url.length > 500) return null;
      visited.add(url);
      
      return new Promise((resolveCert) => {
        const isHttps = url.startsWith('https://');
        const client = isHttps ? https : http;
        
        const req = client.get(url, { timeout }, (res) => {
          const chunks = [];
          res.on('data', chunk => chunks.push(chunk));
          res.on('end', () => {
            try {
              const buffer = Buffer.concat(chunks);
              const contentType = res.headers['content-type'] || '';
              
              if (contentType.includes('application/pkix-cert') || 
                  contentType.includes('application/x-x509-ca-cert') || 
                  contentType.includes('application/x-x509-server-cert') ||
                  url.endsWith('.cer') || url.endsWith('.crt')) {
                try {
                  const x509 = new crypto.X509Certificate(buffer);
                  resolveCert(x509);
                  return;
                } catch (e) {}
                
                try {
                  const base64 = buffer.toString('base64');
                  const pem = '-----BEGIN CERTIFICATE-----\n' + 
                    base64.match(/.{1,64}/g)?.join('\n') + '\n-----END CERTIFICATE-----';
                  const x509 = new crypto.X509Certificate(pem);
                  resolveCert(x509);
                  return;
                } catch (e) {}
              }
              
              if (contentType.includes('pkcs7') || 
                  contentType.includes('application/x-pkcs7') ||
                  url.endsWith('.p7c') || url.endsWith('.p7b')) {
                const pemStr = buffer.toString('utf8');
                const certMatches = pemStr.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
                if (certMatches && certMatches.length > 0) {
                  try {
                    const x509 = new crypto.X509Certificate(certMatches[0]);
                    resolveCert(x509);
                    return;
                  } catch (e) {}
                }
                
                try {
                  const base64Data = pemStr.replace(/-----[\w\s]+-----/g, '').replace(/\s/g, '');
                  const der = Buffer.from(base64Data, 'base64');
                  const x509 = new crypto.X509Certificate(der);
                  resolveCert(x509);
                  return;
                } catch (e) {}
              }
              
              const pemStr = buffer.toString('utf8');
              const certMatches = pemStr.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
              if (certMatches && certMatches.length > 0) {
                try {
                  const x509 = new crypto.X509Certificate(certMatches[0]);
                  resolveCert(x509);
                  return;
                } catch (e) {}
              }
              
              resolveCert(null);
            } catch (e) {
              resolveCert(null);
            }
          });
        });
        
        req.on('error', () => resolveCert(null));
        req.on('timeout', () => { req.destroy(); resolveCert(null); });
      });
    }
    
    // X509Certificate.subject/issuer are multiline strings ("CN=WE1\nO=...\n").
    // getPeerCertificate() returns objects with .CN, .O etc.
    // We must handle both when checking self-signed status.
    function isCertSelfSigned(cert) {
      if (!cert) return false;
      const sub = cert.subject;
      const iss = cert.issuer;
      if (typeof sub === 'string' && typeof iss === 'string') {
        return sub.trim() === iss.trim();
      }
      // Object format (getPeerCertificate)
      if (sub && iss && sub.CN && iss.CN) return sub.CN === iss.CN;
      return false;
    }

    async function buildChain(currentCert, depth = 0) {
      if (!currentCert || depth > 5) return;

      // Only treat as root (stop) if truly self-signed — NOT just any CA cert.
      // Intermediate CAs also have isCA=true but are NOT self-signed.
      if (isCertSelfSigned(currentCert) && depth > 0) {
        intermediates.push(certToObject(currentCert));
        return;
      }

      const aiaUrl = getAIAUrl(currentCert);
      if (aiaUrl) {
        const nextCert = await fetchCert(aiaUrl);
        if (nextCert) {
          intermediates.push(certToObject(nextCert));
          // Continue up the chain unless this cert is the root (self-signed)
          if (!isCertSelfSigned(nextCert)) {
            await buildChain(nextCert, depth + 1);
          }
        }
      }
    }
    
    (async () => {
      if (leafCert) {
        // Step 1: Walk the chain already provided by the TLS handshake.
        // getPeerCertificate(true) links certs via .issuerCertificate with
        // a self-reference at the root — detect cycles by fingerprint.
        let lastTlsCert = leafCert;
        const seenFP = new Set([leafCert.fingerprint256].filter(Boolean));
        let current = leafCert.issuerCertificate;
        while (current) {
          const fp = current.fingerprint256 || current.fingerprint;
          if (!fp || seenFP.has(fp)) break; // circular ref = root pointing to itself
          seenFP.add(fp);
          intermediates.push(certToObject(current));
          lastTlsCert = current;
          current = current.issuerCertificate;
        }

        // Step 2: AIA-chase from the last TLS cert to pick up any remaining
        // intermediates the server didn't send (e.g. cross-signed root).
        if (!isCertSelfSigned(lastTlsCert)) {
          await buildChain(lastTlsCert, Math.max(1, intermediates.length));
        }
      }
      resolve(intermediates);
    })();
  });
}

const app = express();
const PORT = process.env.PORT || 3000;
const DEFAULT_PORTS = [21, 22, 25, 80, 110, 143, 443, 465, 993, 995, 3306, 5432, 8080];
const DEFAULT_ALLOWED_ORIGINS = [
  'http://localhost:3000', 
  'http://127.0.0.1:3000', 
  'https://dns.hetops.dev', 
  'http://dns.hetops.dev'
];
const configuredOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
const ALLOWED_ORIGINS = new Set(configuredOrigins.length > 0 ? configuredOrigins : DEFAULT_ALLOWED_ORIGINS);

app.use(express.json());

// CORS policy: only allow configured origins for browser-based calls.
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return res.status(403).json({ error: 'Origin is not allowed' });
  }

  if (origin) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Vary', 'Origin');
  }

  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
});

app.set('trust proxy', 2);

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please retry in a minute.' }
});

const heavyApiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded for intensive checks. Please slow down.' }
});

app.use('/api', apiLimiter);
app.use(express.static(path.join(__dirname, 'public')));

const RESOLVER_PROFILES = {
  balanced: ['8.8.8.8', '1.1.1.1'],
  google: ['8.8.8.8', '8.8.4.4'],
  cloudflare: ['1.1.1.1', '1.0.0.1'],
  quad9: ['9.9.9.9', '149.112.112.112'],
  opendns: ['208.67.222.222', '208.67.220.220'],
  system: null
};

const PROPAGATION_RESOLVERS = [
  { name: 'Google', ip: '8.8.8.8', location: 'United States' },
  { name: 'Google 2', ip: '8.8.4.4', location: 'United States' },
  { name: 'Cloudflare', ip: '1.1.1.1', location: 'Global CDN' },
  { name: 'Cloudflare 2', ip: '1.0.0.1', location: 'Global CDN' },
  { name: 'Quad9', ip: '9.9.9.9', location: 'Global (Secure)' },
  { name: 'OpenDNS', ip: '208.67.222.222', location: 'United States' },
  { name: 'OpenDNS 2', ip: '208.67.220.220', location: 'United States' },
  { name: 'Comodo Secure', ip: '8.26.56.26', location: 'United States' },
  { name: 'Level3', ip: '209.244.0.3', location: 'United States' },
  { name: 'Verisign', ip: '64.6.64.6', location: 'United States' },
];

const recordTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA'];
const DEFAULT_DISCOVERY_WORDLIST = [
  'www', 'api', 'dev', 'app', 'staging', 'beta', 'admin', 'portal', 'dashboard', 'cdn',
  'static', 'assets', 'img', 'media', 'blog', 'docs', 'status', 'mail', 'smtp', 'imap',
  'pop', 'ftp', 'vpn', 'm', 'shop', 'auth', 'login', 'gateway', 'edge', 'test'
];

function createResolver(profileName = 'balanced') {
  const profile = String(profileName || 'balanced').toLowerCase();
  const servers = RESOLVER_PROFILES[profile] ?? RESOLVER_PROFILES.balanced;
  const resolver = new Resolver();
  if (Array.isArray(servers)) resolver.setServers(servers);
  return { resolver, profile, servers };
}

function normalizeDomain(input) {
  if (typeof input !== 'string' || input.length > 256) return '';
  return input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/\.$/, '');
}

function parseDomains(domain, domains) {
  const fromDomain = domain ? [domain] : [];
  const fromDomains = Array.isArray(domains)
    ? domains
    : typeof domains === 'string'
      ? domains.split(/[\n,\s]+/)
      : [];

  const unique = new Set(
    [...fromDomain, ...fromDomains]
      .map(normalizeDomain)
      .filter(Boolean)
  );

  return [...unique].slice(0, 20);
}

function isExpectedDnsMiss(err) {
  return ['ENODATA', 'ENOTFOUND', 'ENODOMAIN', 'ENOTIMP', 'EREFUSED', 'SERVFAIL'].includes(err?.code);
}

function normalizeRecordForComparison(type, record) {
  if (!record) return '';
  const value = String(record.value || '');
  switch (type) {
    case 'MX':
      return `${value}|${record.priority ?? ''}`.toLowerCase();
    case 'SRV':
      return `${value}|${record.priority ?? ''}|${record.weight ?? ''}`.toLowerCase();
    case 'CAA':
      return `${value}|${record.issue ?? ''}|${record.critical ?? ''}`.toLowerCase();
    default:
      return value.toLowerCase();
  }
}

function compareRecordSets(type, recursiveRecords, authoritativeRecords) {
  const recursiveSet = new Set((recursiveRecords || []).map((r) => normalizeRecordForComparison(type, r)));
  const authoritativeSet = new Set((authoritativeRecords || []).map((r) => normalizeRecordForComparison(type, r)));

  const onlyRecursive = [...recursiveSet].filter((v) => !authoritativeSet.has(v));
  const onlyAuthoritative = [...authoritativeSet].filter((v) => !recursiveSet.has(v));

  return {
    matches: onlyRecursive.length === 0 && onlyAuthoritative.length === 0,
    onlyRecursive,
    onlyAuthoritative
  };
}

async function lookupRecord(resolver, domain, type) {
  try {
    let records;
    switch (type) {
      case 'A':
        records = await resolver.resolve4(domain, { ttl: true });
        return records.map((r) => ({ value: r.address || r, ttl: r.ttl }));
      case 'AAAA':
        records = await resolver.resolve6(domain, { ttl: true });
        return records.map((r) => ({ value: r.address || r, ttl: r.ttl }));
      case 'MX':
        records = await resolver.resolveMx(domain);
        return records.map((r) => ({ value: `${r.exchange}`, priority: r.priority }));
      case 'TXT':
        records = await resolver.resolveTxt(domain);
        return records.map((r) => ({ value: r.join('') }));
      case 'NS':
        records = await resolver.resolveNs(domain);
        return records.map((r) => ({ value: r }));
      case 'CNAME':
        records = await resolver.resolveCname(domain);
        return records.map((r) => ({ value: r }));
      case 'SOA':
        const soa = await resolver.resolveSoa(domain);
        return [{ value: soa.nsname, details: soa }];
      case 'SRV':
        records = await resolver.resolveSrv(domain);
        return records.map((r) => ({ value: `${r.name}:${r.port}`, priority: r.priority, weight: r.weight }));
      case 'CAA':
        records = await resolver.resolveCaa(domain);
        return records.map((r) => ({ value: r.value, issue: r.issue, critical: r.critical }));
      case 'PTR':
        records = await resolver.resolvePtr(domain);
        return records.map((r) => ({ value: r }));
      default:
        return [];
    }
  } catch (err) {
    if (isExpectedDnsMiss(err)) return [];
    throw err;
  }
}

async function buildInsights(resolver, domain, lookupResults) {
  const txtValues = (lookupResults.TXT || []).map((r) => String(r.value || '').toLowerCase());
  const hasSpf = txtValues.some((v) => v.startsWith('v=spf1'));

  let hasDmarc = false;
  try {
    const dmarcTxt = await resolver.resolveTxt(`_dmarc.${domain}`);
    hasDmarc = dmarcTxt.some((entry) => entry.join('').toLowerCase().startsWith('v=dmarc1'));
  } catch (err) {
    if (!isExpectedDnsMiss(err)) throw err;
  }

  const mxCount = (lookupResults.MX || []).length;
  const hasCaa = (lookupResults.CAA || []).length > 0;

  const score = [hasSpf, hasDmarc, mxCount > 0, hasCaa].filter(Boolean).length;
  const status = score >= 3 ? 'strong' : score >= 2 ? 'fair' : 'weak';

  return {
    status,
    score,
    checks: {
      spf: hasSpf,
      dmarc: hasDmarc,
      mx: mxCount > 0,
      caa: hasCaa
    },
    notes: [
      hasSpf ? null : 'SPF policy not detected in TXT records.',
      hasDmarc ? null : 'DMARC record not found at _dmarc subdomain.',
      mxCount > 0 ? null : 'No MX records found; inbound email likely unsupported.',
      hasCaa ? null : 'CAA policy not found; certificate issuance is unrestricted.'
    ].filter(Boolean)
  };
}

async function resolveAuthoritativeNameServers(domain) {
  const systemResolver = new Resolver();
  const nsHosts = await systemResolver.resolveNs(domain);

  const nsDetails = await Promise.all(
    nsHosts.slice(0, 4).map(async (host) => {
      try {
        const addresses = await systemResolver.resolve4(host);
        return addresses.map((ip) => ({ host, ip }));
      } catch (err) {
        return [];
      }
    })
  );

  return nsDetails.flat().slice(0, 4);
}

async function buildAuthoritativeComparison(domain, requestedTypes, recursiveResults) {
  try {
    const nameServers = await resolveAuthoritativeNameServers(domain);
    if (nameServers.length === 0) {
      return {
        enabled: true,
        available: false,
        reason: 'No authoritative nameserver IPs resolved.',
        nameservers: [],
        byType: {},
        mismatchedTypes: []
      };
    }

    const byType = {};
    const mismatchedTypes = [];

    await Promise.all(
      requestedTypes.map(async (type) => {
        const authoritativeRecords = [];
        let sampledFrom = null;

        for (const ns of nameServers) {
          const nsResolver = new Resolver();
          nsResolver.setServers([ns.ip]);
          try {
            const records = await lookupRecord(nsResolver, domain, type);
            authoritativeRecords.push(...records);
            sampledFrom = ns;
            break;
          } catch (err) {
            if (!isExpectedDnsMiss(err)) {
              continue;
            }
          }
        }

        const comparison = compareRecordSets(type, recursiveResults[type] || [], authoritativeRecords);
        byType[type] = {
          nameserver: sampledFrom,
          records: authoritativeRecords,
          comparison
        };

        if (!comparison.matches) mismatchedTypes.push(type);
      })
    );

    return {
      enabled: true,
      available: true,
      nameservers: nameServers,
      byType,
      mismatchedTypes
    };
  } catch (err) {
    return {
      enabled: true,
      available: false,
      reason: err.message,
      nameservers: [],
      byType: {},
      mismatchedTypes: []
    };
  }
}

async function resolveCnameChain(resolver, hostname, maxDepth = 8) {
  const chain = [];
  const visited = new Set();
  let current = hostname;

  for (let i = 0; i < maxDepth; i++) {
    if (visited.has(current)) break;
    visited.add(current);

    try {
      const cnames = await resolver.resolveCname(current);
      if (!cnames || cnames.length === 0) break;
      const next = cnames[0];
      chain.push({ from: current, to: next });
      current = next;
    } catch (err) {
      if (isExpectedDnsMiss(err)) break;
      throw err;
    }
  }

  return {
    chain,
    finalHost: chain.length ? chain[chain.length - 1].to : hostname,
    depth: chain.length
  };
}

async function discoverSubdomains(resolver, domain, customWordlist) {
  const words = Array.isArray(customWordlist) && customWordlist.length > 0
    ? customWordlist.map((w) => String(w).trim().toLowerCase()).filter(Boolean)
    : DEFAULT_DISCOVERY_WORDLIST;

  const uniqueWords = [...new Set(words)].slice(0, 100);
  const hosts = [];

  await Promise.all(
    uniqueWords.map(async (prefix) => {
      const host = `${prefix}.${domain}`;

      try {
        const [a, aaaa, cname] = await Promise.all([
          lookupRecord(resolver, host, 'A'),
          lookupRecord(resolver, host, 'AAAA'),
          lookupRecord(resolver, host, 'CNAME')
        ]);

        const found = a.length > 0 || aaaa.length > 0 || cname.length > 0;
        if (!found) return;

        const cnameChain = await resolveCnameChain(resolver, host);
        let finalA = [];
        let finalAAAA = [];

        if (cnameChain.finalHost && cnameChain.finalHost !== host) {
          [finalA, finalAAAA] = await Promise.all([
            lookupRecord(resolver, cnameChain.finalHost, 'A'),
            lookupRecord(resolver, cnameChain.finalHost, 'AAAA')
          ]);
        }

        hosts.push({
          host,
          records: {
            A: a,
            AAAA: aaaa,
            CNAME: cname
          },
          cnameChain,
          finalTarget: {
            host: cnameChain.finalHost,
            A: finalA,
            AAAA: finalAAAA
          }
        });
      } catch (err) {
        if (!isExpectedDnsMiss(err)) {
          hosts.push({
            host,
            error: err.message,
            records: { A: [], AAAA: [], CNAME: [] },
            cnameChain: { chain: [], finalHost: host, depth: 0 }
          });
        }
      }
    })
  );

  hosts.sort((x, y) => x.host.localeCompare(y.host));

  return {
    enabled: true,
    scanned: uniqueWords.length,
    found: hosts.length,
    hosts
  };
}

async function runLookupForDomain(resolver, domain, requestedTypes, options = {}) {
  const results = {};
  const errors = {};
  const metrics = {};

  await Promise.all(
    requestedTypes.map(async (type) => {
      const start = Date.now();
      try {
        results[type] = await lookupRecord(resolver, domain, type);
      } catch (err) {
        errors[type] = err.message;
        results[type] = [];
      } finally {
        metrics[type] = { durationMs: Date.now() - start, count: (results[type] || []).length };
      }
    })
  );

  const insights = await buildInsights(resolver, domain, results);
  const authoritative = options.compareAuthoritative
    ? await buildAuthoritativeComparison(domain, requestedTypes, results)
    : { enabled: false };
  const discovery = options.discoverSubdomains
    ? await discoverSubdomains(resolver, domain, options.discoveryWordlist)
    : { enabled: false, scanned: 0, found: 0, hosts: [] };
  const totalRecords = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);

  return {
    domain,
    results,
    errors,
    metrics,
    insights,
    authoritative,
    discovery,
    totals: {
      records: totalRecords,
      errorTypes: Object.keys(errors).length
    }
  };
}

function runWithConcurrency(items, concurrency, task) {
  const output = new Array(items.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < items.length) {
      const currentIndex = nextIndex;
      nextIndex += 1;
      output[currentIndex] = await task(items[currentIndex]);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => worker());
  return Promise.all(workers).then(() => output);
}

app.post('/api/dns-lookup', heavyApiLimiter, async (req, res) => {
  const {
    domain,
    domains,
    types,
    resolver: resolverProfile,
    compareAuthoritative = false,
    discoverSubdomains: discoverSubdomainsFlag = false,
    discoveryWordlist
  } = req.body || {};

  const requestedDomains = parseDomains(domain, domains);
  if (requestedDomains.length === 0) {
    return res.status(400).json({ error: 'At least one domain is required' });
  }

  const requestedTypes = (Array.isArray(types) && types.length > 0 ? types : recordTypes)
    .map((t) => String(t).toUpperCase())
    .filter((t) => recordTypes.includes(t));

  if (requestedTypes.length === 0) {
    return res.status(400).json({ error: 'No valid DNS record types selected' });
  }

  const { resolver, profile, servers } = createResolver(resolverProfile);
  const startedAt = Date.now();

  const lookups = await Promise.all(
    requestedDomains.map((d) => runLookupForDomain(resolver, d, requestedTypes, {
      compareAuthoritative: Boolean(compareAuthoritative),
      discoverSubdomains: Boolean(discoverSubdomainsFlag),
      discoveryWordlist
    }))
  );

  const durationMs = Date.now() - startedAt;
  const totalRecords = lookups.reduce((sum, l) => sum + l.totals.records, 0);
  const totalErrors = lookups.reduce((sum, l) => sum + l.totals.errorTypes, 0);
  const discoveredHosts = lookups.reduce((sum, l) => sum + (l.discovery?.found || 0), 0);
  const discoveredScanned = lookups.reduce((sum, l) => sum + (l.discovery?.scanned || 0), 0);

  const payload = {
    timestamp: new Date().toISOString(),
    durationMs,
    resolver: {
      profile,
      servers: servers || dns.getServers()
    },
    query: {
      domains: requestedDomains,
      types: requestedTypes,
      compareAuthoritative: Boolean(compareAuthoritative),
      discoverSubdomains: Boolean(discoverSubdomainsFlag)
    },
    lookups,
    summary: {
      domains: lookups.length,
      totalRecords,
      totalErrors,
      discoveredHosts,
      discoveredScanned
    }
  };

  if (lookups.length === 1) {
    payload.domain = lookups[0].domain;
    payload.results = lookups[0].results;
    payload.errors = lookups[0].errors;
    payload.metrics = lookups[0].metrics;
    payload.insights = lookups[0].insights;
    payload.authoritative = lookups[0].authoritative;
    payload.discovery = lookups[0].discovery;
  }

  res.json(payload);
});

app.post('/api/port-scan', heavyApiLimiter, async (req, res) => {
  const { domain, ports } = req.body;
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const requestedPorts = ports === undefined ? DEFAULT_PORTS : ports;
  if (!Array.isArray(requestedPorts) || requestedPorts.length === 0) {
    return res.status(400).json({ error: 'Ports must be a non-empty array' });
  }

  const normalizedPorts = [...new Set(requestedPorts.map((port) => Number(port)))];
  const hasInvalidPort = normalizedPorts.some(
    (port) => !Number.isInteger(port) || port < 1 || port > 65535
  );

  if (hasInvalidPort) {
    return res.status(400).json({ error: 'All ports must be integers between 1 and 65535' });
  }

  if (normalizedPorts.length > 30) {
    return res.status(400).json({ error: 'You can scan up to 30 ports per request' });
  }
  
  const scanPort = (port) => {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(2500);
      let isOpen = false;
      socket.on('connect', () => { isOpen = true; socket.destroy(); });
      socket.on('timeout', () => { socket.destroy(); });
      socket.on('error', () => { socket.destroy(); });
      socket.on('close', () => { resolve({ port, open: isOpen }); });
      socket.connect(port, host);
    });
  };

  try {
    const results = await runWithConcurrency(normalizedPorts, 10, scanPort);
    res.json({ domain: host, ports: results });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Port scan failed' });
  }
});

app.post('/api/whois', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body;
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const whoisPromise = new Promise((resolve, reject) => {
    whois.lookup(host, { follow: 1 }, (err, data) => {
      if (err) reject(err);
      else resolve(data);
    });
  });

  const timer = new Promise((_, reject) => setTimeout(() => reject(new Error('Whois lookup timed out')), 8000));

  try {
    let data = await Promise.race([whoisPromise, timer]);
    
    if (typeof data === 'string' && (data.toLowerCase().includes('rate limit exceeded') || data.toLowerCase().includes('server is being retired') || data.toLowerCase().includes('connection refused'))) {
      try {
        const rdapReq = await fetch(`https://rdap.org/domain/${host}`, { headers: { 'Accept': 'application/rdap+json' }, signal: AbortSignal.timeout(5000) });
        if (rdapReq.ok) {
          const rdapData = await rdapReq.json();
          let lines = [];
          if (rdapData.ldhName) lines.push(`Domain Name: ${rdapData.ldhName}`);
          if (rdapData.handle) lines.push(`Registry Domain ID: ${rdapData.handle}`);
          (rdapData.events || []).forEach(e => {
            if (e.eventAction === 'registration') lines.push(`Creation Date: ${e.eventDate}`);
            if (e.eventAction === 'expiration') lines.push(`Registry Expiry Date: ${e.eventDate}`);
            if (e.eventAction === 'last changed') lines.push(`Updated Date: ${e.eventDate}`);
          });
          (rdapData.status || []).forEach(s => lines.push(`Domain Status: ${s}`));
          (rdapData.nameservers || []).forEach(ns => lines.push(`Name Server: ${ns.ldhName}`));
          (rdapData.entities || []).forEach(ent => {
            if (ent.roles && ent.roles.includes('registrar')) {
              const vcard = ent.vcardArray && ent.vcardArray[1];
              if (vcard) { const fn = vcard.find(item => item[0] === 'fn'); if (fn) lines.push(`Registrar: ${fn[3]}`); }
              if (ent.publicIds) { const iana = ent.publicIds.find(id => id.type === 'IANA Registrar ID'); if (iana) lines.push(`Registrar IANA ID: ${iana.identifier}`); }
            }
          });
          data = lines.join('\n') + '\n\n--- ORIGINAL BLOCKED RESPONSE ---\n\n' + data;
        }
      } catch (e) {
        // Continue silently if fallback fails
      }
    }

    res.json({ domain: host, rawData: data });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Whois lookup failed' });
  }
});

app.post('/api/geoip', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body;
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });
  
  const resolver = new Resolver();
  let ip = host;
  try {
    const addresses = await resolver.resolve4(host);
    if (addresses.length) ip = addresses[0];
  } catch (err) {
    // Domain may already be an IP or only resolve through non-A records.
  }

  const geoReq = https.get(`https://ipwho.is/${encodeURIComponent(ip)}`, { timeout: 5000 }, (response) => {
    if (response.statusCode && response.statusCode >= 400) {
      if (!res.headersSent) res.status(502).json({ error: `GeoIP provider returned HTTP ${response.statusCode}` });
      return;
    }

    let data = '';
    response.on('data', (chunk) => data += chunk);
    response.on('end', () => {
      if (res.headersSent) return;
      try {
        const parsed = JSON.parse(data);
        if (!parsed.success) {
          return res.status(502).json({ error: parsed.message || 'GeoIP lookup failed' });
        }
        res.json({
          target: ip,
          geo: {
            city: parsed.city,
            region: parsed.region,
            country_name: parsed.country,
            org: parsed.connection?.org,
            asn: parsed.connection?.asn
          }
        });
      } catch (err) {
        res.status(500).json({ error: 'Failed to parse GeoIP data' });
      }
    });
  });

  geoReq.on('error', (err) => {
    if (!res.headersSent) res.status(500).json({ error: err.message || 'GeoIP fetch failed' });
  });

  geoReq.on('timeout', () => {
    geoReq.destroy();
    if (!res.headersSent) res.status(504).json({ error: 'GeoIP request timed out' });
  });
});

app.post('/api/blacklist-check', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body;
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  // Only include reputable IP-based DNSBLs with low false-positive rates.
  // Notes on excluded lists:
  //   xbl/sbl.spamhaus.org — already included inside zen.spamhaus.org (duplicates)
  //   multi.uribl.com      — URI list, not for IP lookups (always wrong for IPs)
  //   dnsbl.sorbs.net      — extremely aggressive; lists entire cloud/VPS ranges
  //   dnsbl-1.uceprotect.net — /24 network-level listing causes false positives for clean IPs
  const blacklists = [
    'zen.spamhaus.org',       // Spamhaus combined (SBL + XBL + PBL) — most authoritative
    'b.barracudacentral.org', // Barracuda Reputation Block List
    'bl.spamcop.net',         // SpamCop DNSBL
    'psbl.surriel.com',       // Passive Spam Block List — low false-positive rate
    'ix.dnsbl.manitu.net',    // Nixspam — reputable, low false positives
  ];
  const resolver = new Resolver({ timeout: 3000, tries: 1 });
  let ips = [];

  try {
    ips = await resolver.resolve4(host);
  } catch (err) {}
  
  try {
    const mx = await resolver.resolveMx(host);
    for (const record of mx.slice(0, 3)) { // Limit to 3 MX records
      try {
        const a = await resolver.resolve4(record.exchange);
        ips.push(...a);
      } catch (err) {}
    }
  } catch (err) {}

  ips = [...new Set(ips)];
  if (!ips.length) return res.json({ domain: host, error: 'No IPs found to check for blacklist.' });

  const results = [];
  try {
    await Promise.all(ips.slice(0, 5).map(async (ip) => { // Limit to 5 IPs check
      const reversedIp = ip.split('.').reverse().join('.');
      await Promise.all(blacklists.map(async (bl) => {
        const query = `${reversedIp}.${bl}`;
        try {
          const addresses = await resolver.resolve4(query);
          // Spamhaus and other DNSBLs return 127.255.255.254 or 127.255.255.255 
          // to indicate that you are blocked from querying them (usually because
          // you are using a public DNS resolver like 8.8.8.8 or 1.1.1.1).
          // We must NOT treat these as "listed" hits.
          const isBlockedQuery = addresses.some(ip => ip === '127.255.255.254' || ip === '127.255.255.255');
          
          if (isBlockedQuery) {
            results.push({ ip, blacklist: bl, listed: false, error: 'Query Limit/Blocked by Public DNS' });
          } else {
            results.push({ ip, blacklist: bl, listed: true, details: addresses });
          }
        } catch (err) {
          if (err.code === 'ENOTFOUND') {
            results.push({ ip, blacklist: bl, listed: false });
          } else {
            results.push({ ip, blacklist: bl, listed: false, error: err.code });
          }
        }
      }));
    }));
    res.json({ domain: host, IPsChecked: ips.length, results });
  } catch(err) {
    res.status(500).json({ error: 'Blacklist check timeout or failure' });
  }
});

function analyzeCipherSuite(cipher) {
  if (!cipher) return { pfs: false, rating: 'unknown', issues: [] };
  
  const issues = [];
  let rating = 'good';
  const name = cipher.name || '';
  
  const pfsCiphers = ['ECDHE', 'DHE', 'CHACHA20'];
  const pfs = pfsCiphers.some(c => name.includes(c));
  
  const weakCiphers = ['RC4', 'DES', '3DES', 'MD5', 'SHA1'];
  const hasWeak = weakCiphers.some(c => name.includes(c));
  
  const ecdheCurves = ['secp256r1', 'secp384r1', 'secp521r1', 'x25519'];
  const modernCurves = ['secp256r1', 'secp384r1', 'secp521r1'];
  
  if (hasWeak) {
    issues.push('Weak cipher suite detected');
    rating = 'critical';
  } else if (cipher.bits && cipher.bits < 128) {
    issues.push('Key size below 128 bits');
    rating = 'poor';
  }
  
  if (!pfs) {
    issues.push('No Perfect Forward Secrecy');
    if (rating === 'good') rating = 'warning';
  }
  
  if (cipher.version === 'TLSv1' || cipher.version === 'TLSv1.1') {
    issues.push('Deprecated TLS version');
    rating = 'critical';
  }
  
  return { pfs, rating, issues, details: cipher };
}

function analyzeCertificateChain(cert, certChain) {
  const chain = [];
  const issues = [];
  let rating = 'good';
  
  const now = new Date();
  
  if (cert && cert.raw) {
    const leaf = {
      type: 'leaf',
      subject: cert.subject ? {
        CN: cert.subject.CN,
        O: cert.subject.O,
        OU: cert.subject.OU
      } : null,
      issuer: cert.issuer ? {
        CN: cert.issuer.CN,
        O: cert.issuer.O,
        OU: cert.issuer.OU
      } : null,
      validFrom: cert.valid_from,
      validTo: cert.valid_to,
      serialNumber: cert.serialNumber,
      fingerprint: cert.fingerprint,
      fingerprint256: cert.fingerprint256,
      keyAlgorithm: cert.keyAlgorithm,
      keyBits: cert.bits,
      signatureAlgorithm: cert.signatureAlgorithm,
      extKeyUsage: cert.extKeyUsage,
      keyUsage: cert.keyUsage,
      subjectAltName: cert.subjectaltname,
      ocspURI: cert.ocspURI,
      isCA: cert.isCA,
      parsed: true
    };
    
    if (cert.valid_from && cert.valid_to) {
      const validFrom = new Date(cert.valid_from);
      const validTo = new Date(cert.valid_to);
      const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
      
      if (now < validFrom) {
        issues.push('Certificate not yet valid');
        rating = 'error';
      } else if (now > validTo) {
        issues.push('Certificate expired');
        rating = 'critical';
      } else if (daysRemaining < 30) {
        issues.push(`Certificate expires in ${daysRemaining} days`);
        if (rating !== 'critical') rating = 'warning';
      }
    }
    
    chain.push(leaf);
  }
  
  if (certChain && certChain.length > 0) {
    certChain.forEach((intermediate, index) => {
      if (intermediate && intermediate.raw) {
        const validFrom = intermediate.valid_from ? new Date(intermediate.valid_from) : null;
        const validTo = intermediate.valid_to ? new Date(intermediate.valid_to) : null;
        
        if (validTo && now > validTo) {
          issues.push(`Intermediate certificate ${index + 1} expired`);
          if (rating !== 'critical') rating = 'warning';
        }
        
        chain.push({
          type: 'intermediate',
          depth: index + 1,
          subject: intermediate.subject ? {
            CN: intermediate.subject.CN,
            O: intermediate.subject.O,
            OU: intermediate.subject.OU
          } : null,
          issuer: intermediate.issuer ? {
            CN: intermediate.issuer.CN,
            O: intermediate.issuer.O
          } : null,
          validFrom: intermediate.valid_from,
          validTo: intermediate.valid_to,
          serialNumber: intermediate.serialNumber,
          fingerprint256: intermediate.fingerprint256,
          isCA: intermediate.isCA,
          parsed: true
        });
      }
    });
  }
  
  if (chain.length < 2 && rating !== 'critical') {
    issues.push('Incomplete certificate chain - may cause trust issues');
    if (rating === 'good') rating = 'warning';
  }
  
  return { chain, issues, rating };
}

function analyzeSecurityHeaders(headers) {
  const analysis = {
    headers: {},
    checks: {},
    score: 0,
    maxScore: 100,
    rating: 'poor',
    recommendations: []
  };
  
  const lowerHeaders = {};
  for (const [key, value] of Object.entries(headers || {})) {
    lowerHeaders[key.toLowerCase()] = value;
  }
  
  const checks = [
    { name: 'Strict-Transport-Security', key: 'strict-transport-security', weight: 20, good: false },
    { name: 'Content-Security-Policy', key: 'content-security-policy', weight: 15, good: false },
    { name: 'X-Content-Type-Options', key: 'x-content-type-options', weight: 10, good: false },
    { name: 'X-Frame-Options', key: 'x-frame-options', weight: 10, good: false },
    { name: 'X-XSS-Protection', key: 'x-xss-protection', weight: 5, good: false },
    { name: 'Referrer-Policy', key: 'referrer-policy', weight: 10, good: false },
    { name: 'Permissions-Policy', key: 'permissions-policy', weight: 10, good: false },
    { name: 'Cache-Control', key: 'cache-control', weight: 5, good: true },
    { name: 'X-Powered-By', key: 'x-powered-by', weight: 5, good: true, inverted: true },
    { name: 'Server', key: 'server', weight: 5, good: true, inverted: true },
    { name: 'Public-Key-Pins', key: 'public-key-pins', weight: 5, good: false, deprecated: true }
  ];
  
  checks.forEach(check => {
    const value = lowerHeaders[check.key];
    analysis.headers[check.name] = value || null;
    
    let passed = false;
    let status = 'missing';
    let detail = '';
    
    if (value) {
      status = 'present';
      if (check.inverted) {
        passed = false;
        detail = 'Header exposed - consider removing';
      } else if (check.deprecated) {
        passed = false;
        detail = 'Deprecated header - should be removed';
        analysis.recommendations.push(`${check.name} is deprecated and should be removed`);
      } else {
        passed = true;
        const valLower = value.toLowerCase();
        if (check.key === 'strict-transport-security') {
          const maxAge = valLower.match(/max-age=(\d+)/);
          if (maxAge && parseInt(maxAge[1]) >= 31536000) {
            detail = `max-age: ${maxAge[1]}s (good)`;
            if (valLower.includes('includeSubDomains')) detail += ', includes subdomains';
            if (valLower.includes('preload')) detail += ', preload enabled';
          } else {
            passed = false;
            detail = `max-age too short (${maxAge ? maxAge[1] : 'missing'}s)`;
            analysis.recommendations.push('HSTS max-age should be at least 31536000 (1 year)');
          }
        } else if (check.key === 'x-content-type-options') {
          if (valLower === 'nosniff') { passed = true; detail = 'nosniff'; }
          else { passed = false; detail = value; }
        } else if (check.key === 'x-frame-options') {
          if (['deny', 'sameorigin'].includes(valLower)) { passed = true; detail = value; }
          else { passed = false; detail = value; analysis.recommendations.push('X-Frame-Options should be DENY or SAMEORIGIN'); }
        } else if (check.key === 'content-security-policy') {
          if (valLower.includes('default-src') || valLower.includes('script-src')) {
            detail = 'Policy with script restrictions';
          } else {
            detail = 'Basic policy';
            analysis.recommendations.push('CSP should include default-src and script-src directives');
          }
        } else if (check.key === 'referrer-policy') {
          const goodPolicies = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];
          if (goodPolicies.includes(valLower)) { passed = true; detail = value; }
          else { detail = value; analysis.recommendations.push('Consider using strict referrer policy like same-origin or strict-origin'); }
        } else if (check.key === 'permissions-policy') {
          passed = true;
          detail = 'Policy configured';
        } else {
          detail = value;
        }
      }
    } else if (!check.inverted && !check.deprecated) {
      if (check.key === 'strict-transport-security') {
        analysis.recommendations.push('Add HSTS header with max-age of at least 31536000');
      } else if (check.key === 'content-security-policy') {
        analysis.recommendations.push('Add Content-Security-Policy to prevent XSS and injection attacks');
      } else if (check.key === 'x-content-type-options') {
        analysis.recommendations.push('Add X-Content-Type-Options: nosniff');
      } else if (check.key === 'x-frame-options') {
        analysis.recommendations.push('Add X-Frame-Options to prevent clickjacking');
      } else if (check.key === 'referrer-policy') {
        analysis.recommendations.push('Add Referrer-Policy header');
      } else if (check.key === 'permissions-policy') {
        analysis.recommendations.push('Consider adding Permissions-Policy to restrict browser features');
      }
    }
    
    analysis.checks[check.name] = {
      present: !!value,
      passed,
      status,
      detail,
      deprecated: check.deprecated || false
    };
    
    if (check.inverted && value) {
      analysis.score += 0;
    } else if (passed) {
      analysis.score += check.weight;
    } else if (!check.deprecated) {
      analysis.score += check.weight * 0.3;
    }
  });
  
  if (analysis.score >= 80) analysis.rating = 'excellent';
  else if (analysis.score >= 60) analysis.rating = 'good';
  else if (analysis.score >= 40) analysis.rating = 'fair';
  else if (analysis.score >= 20) analysis.rating = 'poor';
  else analysis.rating = 'critical';
  
  return analysis;
}

const CIPHER_SUITES = {
  protocols: {
    'TLSv1.3': [
      { name: 'TLS_AES_256_GCM_SHA384', security: 'good', pfs: true, bits: 256 },
      { name: 'TLS_AES_128_GCM_SHA256', security: 'good', pfs: true, bits: 128 },
      { name: 'TLS_CHACHA20_POLY1305_SHA256', security: 'good', pfs: true, bits: 256 },
    ],
    'TLSv1.2': [
      { name: 'ECDHE-RSA-AES256-GCM-SHA384', security: 'good', pfs: true, bits: 256 },
      { name: 'ECDHE-RSA-AES128-GCM-SHA256', security: 'good', pfs: true, bits: 128 },
      { name: 'ECDHE-RSA-CHACHA20-POLY1305', security: 'good', pfs: true, bits: 256 },
      { name: 'DHE-RSA-AES256-GCM-SHA384', security: 'good', pfs: true, bits: 256 },
      { name: 'DHE-RSA-AES128-GCM-SHA256', security: 'good', pfs: true, bits: 128 },
      { name: 'AES256-GCM-SHA384', security: 'warning', pfs: false, bits: 256 },
      { name: 'AES128-GCM-SHA256', security: 'warning', pfs: false, bits: 128 },
      { name: 'AES256-SHA256', security: 'warning', pfs: false, bits: 256 },
      { name: 'AES128-SHA256', security: 'warning', pfs: false, bits: 128 },
      { name: 'AES256-SHA', security: 'warning', pfs: false, bits: 256 },
      { name: 'AES128-SHA', security: 'warning', pfs: false, bits: 128 },
      { name: 'DES-CBC3-SHA', security: 'critical', pfs: false, bits: 112 },
      { name: 'RC4-SHA', security: 'critical', pfs: false, bits: 128 },
      { name: 'RC4-MD5', security: 'critical', pfs: false, bits: 128 },
    ],
    'TLSv1.1': [
      { name: 'AES256-SHA', security: 'critical', pfs: false, bits: 256 },
      { name: 'AES128-SHA', security: 'critical', pfs: false, bits: 128 },
      { name: 'DES-CBC3-SHA', security: 'critical', pfs: false, bits: 112 },
      { name: 'RC4-SHA', security: 'critical', pfs: false, bits: 128 },
    ],
    'TLSv1.0': [
      { name: 'AES256-SHA', security: 'critical', pfs: false, bits: 256 },
      { name: 'AES128-SHA', security: 'critical', pfs: false, bits: 128 },
      { name: 'DES-CBC3-SHA', security: 'critical', pfs: false, bits: 112 },
      { name: 'RC4-SHA', security: 'critical', pfs: false, bits: 128 },
      { name: 'RC4-MD5', security: 'critical', pfs: false, bits: 128 },
    ],
    'SSLv3': [
      { name: 'DES-CBC3-SHA', security: 'critical', pfs: false, bits: 112 },
      { name: 'RC4-SHA', security: 'critical', pfs: false, bits: 128 },
      { name: 'RC4-MD5', security: 'critical', pfs: false, bits: 128 },
    ],
  },
  weakPatterns: [/RC4/i, /DES/i, /MD5/i, /NULL/i, /EXPORT/i, /anon/i, /kRB5/i, /aDSS/i],
  pfsPatterns: [/ECDHE/i, /DHE/i, /CHACHA20/i],
};

function analyzeVulnerabilities(protocol, cipherName) {
  const vuln = {
    BEAST: { vulnerable: false, details: '' },
    POODLE: { vulnerable: false, details: '' },
    POODLE_TLS: { vulnerable: false, details: '' },
    SWEET32: { vulnerable: false, details: '' },
    ROBOT: { vulnerable: false, details: '' },
    CRIME: { vulnerable: false, details: '' },
    BREACH: { vulnerable: false, details: '' },
    LOGJAM: { vulnerable: false, details: '' },
    DROWN: { vulnerable: false, details: '' },
    FREAK: { vulnerable: false, details: '' },
    BARMITZVA: { vulnerable: false, details: '' },
  };

  if (protocol === 'TLSv1.0' || protocol === 'TLSv1.1' || protocol === 'SSLv3') {
    vuln.POODLE.vulnerable = true;
    vuln.POODLE.details = `${protocol} is vulnerable to POODLE attack`;
  }

  if (protocol === 'TLSv1.0') {
    vuln.BEAST.vulnerable = true;
    vuln.BEAST.details = 'TLS 1.0 is vulnerable to BEAST attack (1/n-1 record splitting not effective)';
  }

  if (cipherName && /RC4/i.test(cipherName)) {
    vuln.SWEET32.vulnerable = true;
    vuln.SWEET32.details = 'RC4 cipher is vulnerable to SWEET32 birthday attack';
  }

  if (cipherName && /64/i.test(cipherName) && !/SHA512/i.test(cipherName)) {
    vuln.SWEET32.vulnerable = true;
    vuln.SWEET32.details = '64-bit block cipher vulnerable to SWEET32 birthday attack';
  }

  if (protocol === 'TLSv1.2' && cipherName && /CBC/i.test(cipherName)) {
    vuln.POODLE_TLS.vulnerable = true;
    vuln.POODLE_TLS.details = 'CBC mode ciphers in TLS 1.2 may be vulnerable to POODLE variant';
  }

  if (cipherName && /DHE/i.test(cipherName)) {
    vuln.LOGJAM.vulnerable = true;
    vuln.LOGJAM.details = 'DHE cipher may be vulnerable to LOGJAM - ensure DH key size >= 2048 bits';
  }

  if (protocol === 'SSLv3') {
    vuln.POODLE.vulnerable = true;
    vuln.POODLE.details = 'SSLv3 is deprecated and vulnerable to POODLE';
    vuln.CRIME.details = 'SSLv3 vulnerable to CRIME compression attack';
  }

  return vuln;
}

function calculateSslLabsGrade(score) {
  if (score >= 100) return { letter: 'A+', color: '#00ff00' };
  if (score >= 90)  return { letter: 'A',  color: '#00cc00' };
  if (score >= 80)  return { letter: 'A-', color: '#66cc00' };
  if (score >= 70)  return { letter: 'B',  color: '#cccc00' };
  if (score >= 60)  return { letter: 'C',  color: '#ff9900' };
  if (score >= 50)  return { letter: 'D',  color: '#ff6600' };
  if (score >= 40)  return { letter: 'E',  color: '#ff3300' };
  return { letter: 'F', color: '#ff0000' };
}

function calculateSslLabsScore(sslData) {
  let score = 100;
  const issues = [];
  let capScore = null; // hard cap from critical issues

  // ── Certificate issues ─────────────────────────────────────────
  if (sslData.certificate?.expired) {
    capScore = 0; issues.push('Certificate expired');
  }
  if (sslData.certificate?.daysRemaining < 30 && !sslData.certificate?.expired) {
    score -= 10; issues.push('Certificate expires soon (< 30 days)');
  }
  if (sslData.certificate?.sha1Signed) {
    score -= 30; if (capScore === null || capScore > 60) capScore = 60;
    issues.push('Certificate signed with SHA-1 (deprecated, insecure)');
  }
  if (sslData.certificate?.keyStrength === 'weak') {
    score -= 20; issues.push(`Weak key: ${sslData.certificate.keyBits}-bit ${sslData.certificate.keyType}`);
  }
  if (sslData.certificate?.longLivedCert) {
    score -= 5; issues.push('Certificate validity period exceeds 398 days (industry max)');
  }
  if (sslData.certificate?.chainIssues) {
    score -= sslData.certificate.chainIssues * 10; issues.push('Incomplete certificate chain');
  }

  // ── Protocol support ───────────────────────────────────────────
  if (!sslData.protocols?.tls13) { score -= 15; }
  if (!sslData.protocols?.tls12) { score -= 10; }
  if (sslData.protocols?.sslv3) {
    capScore = 0; issues.push('SSLv3 enabled — critical vulnerability (POODLE)');
  }
  if (sslData.protocols?.tls10) { score -= 15; issues.push('TLS 1.0 enabled (deprecated)'); }
  if (sslData.protocols?.tls11) { score -= 10; issues.push('TLS 1.1 enabled (deprecated)'); }

  // ── PFS & ciphers ──────────────────────────────────────────────
  if (sslData.pfs?.supported === false) { score -= 20; issues.push('No Perfect Forward Secrecy'); }
  else if (sslData.pfs?.supported === 'partial') score -= 10;

  if (sslData.cipherSuites?.usesWeak) { score -= 15; issues.push('Weak cipher suites in use'); }
  if (sslData.cipherSuites?.supportsRc4 || sslData.cipherSuites?.supports3des) score -= 10;

  // ── Known vulnerabilities ──────────────────────────────────────
  if (sslData.vulnerabilities?.BEAST?.vulnerable)     { score -= 10; issues.push('BEAST vulnerability'); }
  if (sslData.vulnerabilities?.POODLE?.vulnerable)    { score -= 30; capScore = 0; issues.push('POODLE vulnerability'); }
  if (sslData.vulnerabilities?.POODLE_TLS?.vulnerable){ score -= 10; issues.push('POODLE TLS'); }
  if (sslData.vulnerabilities?.SWEET32?.vulnerable)   { score -= 20; issues.push('SWEET32 vulnerability'); }
  if (sslData.vulnerabilities?.LOGJAM?.vulnerable)    { score -= 10; issues.push('LOGJAM vulnerability'); }
  if (sslData.vulnerabilities?.DROWN?.vulnerable)     { score -= 30; capScore = 0; issues.push('DROWN vulnerability'); }
  if (sslData.vulnerabilities?.FREAK?.vulnerable)     { score -= 15; issues.push('FREAK vulnerability'); }
  if (sslData.vulnerabilities?.RC4?.vulnerable)       { score -= 25; issues.push('RC4 vulnerability'); }

  // ── Misc ───────────────────────────────────────────────────────
  if (!sslData.ocsp?.stapling) score -= 5;

  const raw = Math.max(0, score);
  return { score: capScore !== null ? Math.min(raw, capScore) : raw, issues };
}

function testTlsProtocol(host, port, protocolVersion, minVersion, maxVersion) {
  if (minVersion === 'SSLv3') {
    return Promise.resolve({ supported: false, protocol: protocolVersion, note: 'Not supported by Node.js TLS' });
  }
  return new Promise((resolve) => {
    const options = {
      host,
      port: port || 443,
      servername: host,
      rejectUnauthorized: false,
      minVersion,
      maxVersion,
    };

    const socket = tls.connect(options);
    const timeout = setTimeout(() => {
      socket.destroy();
      resolve({ supported: false, protocol: protocolVersion });
    }, 3000);

    socket.on('secureConnect', () => {
      clearTimeout(timeout);
      const cipher = socket.getCipher();
      const negotiatedProtocol = socket.getProtocol(); // e.g. 'TLSv1.3'
      socket.end();
      // In TLS 1.3, forward secrecy is mandatory — cipher names like
      // TLS_AES_256_GCM_SHA384 don't contain 'ECDHE' but PFS is always present.
      const isTls13 = negotiatedProtocol === 'TLSv1.3';
      resolve({
        supported: true,
        protocol: protocolVersion,
        negotiatedProtocol,
        cipher: cipher?.name,
        bits: cipher?.bits,
        pfs: isTls13 || /ECDHE|DHE|CHACHA20/i.test(cipher?.name || ''),
      });
    });

    socket.on('error', () => {
      clearTimeout(timeout);
      socket.destroy();
      resolve({ supported: false, protocol: protocolVersion });
    });
  });
}

app.post('/api/ssl', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const result = {
    host: host,
    checkedAt: new Date().toISOString(),
    ip: null,
    protocols: {
      tls13: false,
      tls12: false,
      tls11: false,
      tls10: false,
      sslv3: false,
      details: [],
    },
    certificate: {
      subject: null,
      issuer: null,
      validFrom: null,
      validTo: null,
      daysRemaining: null,
      expired: false,
      notYetValid: false,
      serialNumber: null,
      fingerprint: null,
      fingerprint256: null,
      keyAlgorithm: null,
      keyBits: null,
      signatureAlgorithm: null,
      subjectAltNames: [],
      chainIssues: 0,
      chain: [],
    },
    cipherSuites: {
      supported: [],
      usesWeak: false,
      supportsRc4: false,
      supports3des: false,
      supportsNull: false,
      supportsAnon: false,
    },
    pfs: {
      supported: null,
      pfsCiphers: [],
      nonPfsCiphers: [],
    },
    sessionResumption: {
      supported: null,
      sessionTickets: null,
    },
    ocsp: {
      stapling: null,
      mustStaple: null,
      responderURL: null,
    },
    vulnerabilities: {},
    handshakeSimulations: [],
    chainValidation: {
      complete: false,
      trusted: null,
      issues: [],
    },
    serverPreferences: {},
    warnings: [],
    recommendations: [],
    grade: { score: 100, letter: 'A+', color: '#00ff00' },
  };

  try {
    const ip = await new Promise((resolve, reject) => {
      dns.lookup(host, { family: 4 }, (err, address) => {
        if (err) reject(err);
        else resolve(address);
      });
    });
    result.ip = ip;
  } catch (e) {}

  const protocolTests = [
    testTlsProtocol(host, 443, 'TLS 1.3', 'TLSv1.3', 'TLSv1.3'),
    testTlsProtocol(host, 443, 'TLS 1.2', 'TLSv1.2', 'TLSv1.2'),
    testTlsProtocol(host, 443, 'TLS 1.1', 'TLSv1.1', 'TLSv1.1'),
    testTlsProtocol(host, 443, 'TLS 1.0', 'TLSv1', 'TLSv1'),
    testTlsProtocol(host, 443, 'SSL 3.0', 'SSLv3', 'SSLv3'),
  ];

  const protocolResults = await Promise.all(protocolTests);
  
  protocolResults.forEach(r => {
    if (r.supported) {
      if (r.protocol === 'TLS 1.3') result.protocols.tls13 = true;
      if (r.protocol === 'TLS 1.2') result.protocols.tls12 = true;
      if (r.protocol === 'TLS 1.1') result.protocols.tls11 = true;
      if (r.protocol === 'TLS 1.0') result.protocols.tls10 = true;
      if (r.protocol === 'SSL 3.0') result.protocols.sslv3 = true;
      
      result.protocols.details.push({
        protocol: r.protocol,
        supported: true,
        cipher: r.cipher,
        bits: r.bits,
        pfs: r.pfs,
      });

      if (result.cipherSuites.supported.indexOf(r.cipher) === -1) {
        result.cipherSuites.supported.push(r.cipher);
      }
    } else {
      result.protocols.details.push({
        protocol: r.protocol,
        supported: false,
      });
    }
  });

  result.protocols.supportsSslv3 = result.protocols.sslv3;
  result.protocols.supportsTls10 = result.protocols.tls10;
  result.protocols.supportsTls11 = result.protocols.tls11;

  const socket = await new Promise((resolve) => {
    const s = tls.connect({
      host,
      port: 443,
      servername: host,
      rejectUnauthorized: false,
    });
    const timeout = setTimeout(() => {
      s.destroy();
      resolve(null);
    }, 10000);

    s.on('secureConnect', () => {
      clearTimeout(timeout);
      resolve(s);
    });
    s.on('error', () => {
      clearTimeout(timeout);
      resolve(null);
    });
  });

  if (socket) {
    try {
      const cert = socket.getPeerCertificate(true);
      const certChain = socket.getPeerCertificate()?.certificateChain || [];
      
      if (cert) {
        const now = new Date();
        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

        result.certificate = {
          ...result.certificate,
          subject: cert.subject || {},
          issuer: cert.issuer || {},
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          daysRemaining,
          expired: now > validTo,
          notYetValid: now < validFrom,
          serialNumber: cert.serialNumber,
          fingerprint: cert.fingerprint,
          fingerprint256: cert.fingerprint256,
          keyAlgorithm: cert.keyAlgorithm,
          keyBits: cert.bits,
          signatureAlgorithm: cert.signatureAlgorithm,
          subjectAltNames: cert.subjectaltname
            ? cert.subjectaltname.split(', ').filter(s => s.startsWith('DNS:')).map(s => s.replace('DNS:', ''))
            : [],
          ocspURI: cert.ocspURI,
          mustStaple: !!(cert.raw && cert.raw.includes(Buffer.from('2b0601050507011800', 'hex').slice(0, 8))),
        };

        // ── Deep certificate analysis ──────────────────────────────
        const sigAlgo = cert.signatureAlgorithm || '';
        const keyBits = cert.bits || 0;
        const keyAlgo = cert.keyAlgorithm || sigAlgo;
        const isECKey = /ec|ecdsa/i.test(keyAlgo);
        const sanList = result.certificate.subjectAltNames;

        result.certificate.sha1Signed = /sha1/i.test(sigAlgo);
        result.certificate.isWildcard = sanList.some(s => s.startsWith('*.')) || (cert.subject?.CN || '').startsWith('*.');
        result.certificate.keyType = isECKey ? 'EC' : /rsa/i.test(keyAlgo) ? 'RSA' : keyAlgo || 'Unknown';
        result.certificate.keyStrength = isECKey
          ? (keyBits >= 384 ? 'excellent' : keyBits >= 256 ? 'good' : 'weak')
          : (keyBits >= 4096 ? 'excellent' : keyBits >= 2048 ? 'good' : 'weak');

        // EV = has jurisdictionC or businessCategory in subject; OV = has O; DV = no O
        const subj = cert.subject || {};
        result.certificate.certType = (subj.jurisdictionCountry || subj.jurisdictionST || subj.businessCategory)
          ? 'EV' : subj.O ? 'OV' : 'DV';

        // Validity period (how many days was the cert issued for)
        result.certificate.validityPeriodDays = Math.round((new Date(cert.valid_to) - new Date(cert.valid_from)) / 864e5);
        // CAs should not issue certs longer than 398 days (industry standard since 2020)
        result.certificate.longLivedCert = result.certificate.validityPeriodDays > 398;

        result.certificate.sanCount = sanList.length;
        result.certificate.issuerCN = cert.issuer?.CN || cert.issuer?.O || 'Unknown';

        const chainCerts = [cert, ...certChain];

        const fetchedIntermediates = await fetchIntermediateCerts(cert);

        const fullChain = [cert, ...fetchedIntermediates];

        result.certificate.chain = fullChain.map((c, i) => {
          const cNow = new Date();
          const cTo = new Date(c.valid_to || c.validTo);
          const cDays = Math.floor((cTo - cNow) / 864e5);
          const cSigAlgo = c.signatureAlgorithm || '';
          const cKeyAlgo = c.keyAlgorithm || cSigAlgo;
          const cIsEC = /ec|ecdsa/i.test(cKeyAlgo);

          // Normalise subject/issuer — may be a string (X509Certificate) or object (getPeerCertificate)
          function parseDN(dn) {
            if (!dn) return {};
            if (typeof dn === 'object') return dn;
            const out = {};
            for (const line of dn.split('\n')) {
              const eq = line.indexOf('=');
              if (eq > 0) out[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
            }
            return out;
          }
          const subj = parseDN(c.subject);
          const issr = parseDN(c.issuer);
          const selfSigned = subj.CN && issr.CN ? subj.CN === issr.CN
            : typeof c.subject === 'string' && typeof c.issuer === 'string'
              ? c.subject.trim() === c.issuer.trim() : false;

          return {
            type: i === 0 ? 'leaf' : selfSigned ? 'root' : 'intermediate',
            subject: subj,
            issuer: issr,
            validFrom: c.valid_from || c.validFrom,
            validTo: c.valid_to || c.validTo,
            daysRemaining: cDays,
            isExpired: cTo < cNow,
            isCA: !!(c.isCA ?? c.ca),
            serialNumber: c.serialNumber,
            fingerprint: c.fingerprint,
            fingerprint256: c.fingerprint256,
            keyBits: c.bits,
            keyType: cIsEC ? 'EC' : 'RSA',
            signatureAlgorithm: cSigAlgo,
            sha1Signed: /sha1/i.test(cSigAlgo),
            ocspURI: c.ocspURI || null,
            pem: c.PEM || (c.raw ? '-----BEGIN CERTIFICATE-----\n' + c.raw.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----' : null),
          };
        });

        result.certificate.chainIssues = Math.max(0, 2 - fullChain.length);

        if (chainCerts.length < 2) {
          result.chainValidation.issues.push('Incomplete certificate chain');
        }
        result.chainValidation.complete = fullChain.length >= 2;

        // ── CAA vs issuer cross-check ──────────────────────────────
        try {
          const caaResolver = new Resolver();
          const caaRecords = await caaResolver.resolveCaa(host).catch(() => []);
          if (caaRecords.length > 0) {
            const issuers = caaRecords.filter(r => r.issue || r.tag === 'issue' || r.tag === 'issuewild').map(r => (r.value || r.issue || '').toLowerCase().trim());
            const issuerCN = (cert.issuer?.CN || cert.issuer?.O || '').toLowerCase();
            // Map issuer names to known CA domains
            const caaDomainMap = {
              "let's encrypt": 'letsencrypt.org', 'letsencrypt': 'letsencrypt.org',
              "digicert": 'digicert.com', "comodo": 'sectigo.com', "sectigo": 'sectigo.com',
              "globalsign": 'globalsign.com', "entrust": 'entrust.net',
              "godaddy": 'godaddy.com', "amazon": 'amazonaws.com',
              "google trust services": 'pki.goog', "google": 'pki.goog',
              "microsoft": 'microsoft.com', "cloudflare": 'cloudflare.com',
            };
            const expectedDomain = Object.entries(caaDomainMap).find(([k]) => issuerCN.includes(k))?.[1] || null;
            result.certificate.caaMatch = expectedDomain ? issuers.some(i => i === ';' || i.includes(expectedDomain)) : null;
            result.certificate.caaIssuers = issuers;
          }
        } catch (e) {}

        const cipher = socket.getCipher();
        const negotiatedProtocol = socket.getProtocol(); // 'TLSv1.3', 'TLSv1.2', etc.
        const isTls13 = negotiatedProtocol === 'TLSv1.3';

        // If the unrestricted connection negotiated TLS 1.3 but the forced
        // TLS 1.3-only protocol test failed (e.g. env timeout), mark it supported.
        if (isTls13 && !result.protocols.tls13) {
          result.protocols.tls13 = true;
          const idx = result.protocols.details.findIndex(d => d.protocol === 'TLS 1.3');
          if (idx !== -1 && !result.protocols.details[idx].supported) {
            result.protocols.details[idx] = { protocol: 'TLS 1.3', supported: true, cipher: cipher?.name, bits: cipher?.bits, pfs: true };
          } else if (idx === -1) {
            result.protocols.details.unshift({ protocol: 'TLS 1.3', supported: true, cipher: cipher?.name, bits: cipher?.bits, pfs: true });
          }
        }

        if (cipher) {
          // TLS 1.3 always has forward secrecy — ephemeral key exchange is mandatory
          // in the spec. Cipher names like TLS_AES_256_GCM_SHA384 don't say 'ECDHE'
          // but PFS is implicit. Only check cipher name for TLS 1.2 and below.
          result.pfs.supported = isTls13 || /ECDHE|DHE|CHACHA20/i.test(cipher.name);
          result.pfs.pfsCiphers = result.protocols.details.filter(d => d.pfs && d.supported).map(d => d.cipher);
          result.pfs.nonPfsCiphers = result.protocols.details.filter(d => !d.pfs && d.supported).map(d => d.cipher);
        }
      }

      const cipherName = socket.getCipher()?.name;

      result.vulnerabilities = analyzeVulnerabilities(negotiatedProtocol, cipherName);

      if (cert && cert.ocspURI) {
        result.ocsp.stapling = true;
        result.ocsp.responderURL = cert.ocspURI;
      }

      const sessionId = socket.getSession?.();
      if (sessionId) {
        result.sessionResumption.supported = true;
      }

      socket.end();
    } catch (e) {
      if (socket && !socket.destroyed) socket.end();
    }
  }

  result.protocols.details.forEach(p => {
    if (p.cipher) {
      if (/RC4/i.test(p.cipher)) result.cipherSuites.supportsRc4 = true;
      if (/3DES|DES/i.test(p.cipher)) result.cipherSuites.supports3des = true;
      if (/NULL/i.test(p.cipher)) result.cipherSuites.supportsNull = true;
      if (/anon/i.test(p.cipher)) result.cipherSuites.supportsAnon = true;
      if (/RC4|DES|NULL/i.test(p.cipher)) result.cipherSuites.usesWeak = true;
    }
  });

  const clientSimulations = [
    { name: 'Firefox 120', minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3' },
    { name: 'Chrome 120', minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3' },
    { name: 'Safari 17', minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3' },
    { name: 'Edge 120', minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3' },
    { name: 'Android 13', minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' },
    { name: 'Java 8u291', minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' },
    { name: 'IE 11 Win 7', minVersion: 'TLSv1', maxVersion: 'TLSv1.2' },
  ];

  for (const client of clientSimulations) {
    const testResult = await testTlsProtocol(host, 443, client.name, client.minVersion, client.maxVersion);
    result.handshakeSimulations.push({
      client: client.name,
      protocol: testResult.protocol,
      supported: testResult.supported,
      cipher: testResult.cipher,
      pfs: testResult.pfs,
    });
  }

  if (!result.protocols.tls13) result.recommendations.push('Enable TLS 1.3 for best security and performance');
  if (result.protocols.tls11 || result.protocols.tls10) result.recommendations.push('Disable TLS 1.0 and 1.1 - deprecated protocols');
  if (result.protocols.sslv3) result.recommendations.push('Disable SSL 3.0 immediately - critical vulnerability');
  if (!result.pfs.supported) result.recommendations.push('Enable Perfect Forward Secrecy (PFS) with ECDHE');
  if (result.cipherSuites.supportsRc4) result.recommendations.push('Disable RC4 cipher - vulnerable to attacks');
  if (!result.ocsp.stapling) result.recommendations.push('Enable OCSP stapling for better certificate validation');
  if (result.certificate.daysRemaining < 60) result.recommendations.push('Renew certificate soon - expires in ' + result.certificate.daysRemaining + ' days');
  if (result.certificate.chainIssues > 0) result.recommendations.push('Fix certificate chain - incomplete chain detected');

  const { score, issues } = calculateSslLabsScore(result);
  result.warnings = issues;
  result.grade = calculateSslLabsGrade(score);
  result.grade.score = score;

  res.json(result);
});

app.post('/api/ssl-labs', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const fullReport = await new Promise((resolve) => {
    const baseSslResult = {
      host: host,
      reportTime: new Date().toISOString(),
      isPublic: false,
      status: 'READY',
      hostStart: new Date().toISOString(),
      hostEnd: new Date().toISOString(),
      engineVersion: '4.0.0',
      criteriaVersion: '2009q',
      durationMs: 0,
    };

    const endpoint = {
      ipAddress: null,
      serverName: host,
      statusMessage: 'Ready',
      grade: 'T',
      gradeTrustIgnored: 'T',
      isExceptional: false,
      progress: 100,
      details: {
        certChains: [],
        protocols: [],
        supportedCurves: [],
        serverSignature: null,
        compressionMethods: [],
        sessionTickets: [],
        ocspStapling: false,
        staplingRevoked: false,
        sne: false,
        protocolsInfo: [],
        ciphersInfo: [],
        simulationInfo: [],
        issuesInfo: [],
      },
    };

    resolve({ ...baseSslResult, endpoints: [endpoint] });
  });

  const sslData = await new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.ssllabs.com',
      port: 443,
      path: `/api/v3/analyze?host=${encodeURIComponent(host)}&publish=off&all=done&ignoreMismatch=on`,
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
      timeout: 30000,
    };

    const proxyReq = https.request(options, (proxyRes) => {
      let data = '';
      proxyRes.on('data', chunk => data += chunk);
      proxyRes.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve(null);
        }
      });
    });

    proxyReq.on('error', () => resolve(null));
    proxyReq.on('timeout', () => { proxyReq.destroy(); resolve(null); });
    proxyReq.end();
  });

  if (sslData && sslData.endpoints && sslData.endpoints.length > 0) {
    return res.json(sslData);
  }

  const localReport = await new Promise((resolve) => {
    const req = https.request({
      hostname: host,
      port: 443,
      path: '/',
      method: 'GET',
      rejectUnauthorized: false,
      timeout: 10000,
    }, (response) => {
      const socket = response.socket;
      const cert = socket.getPeerCertificate?.(true);
      const cipher = socket.getCipher?.();
      const protocol = socket.getProtocol?.();

      resolve({
        host: host,
        reportTime: new Date().toISOString(),
        endpoints: [{
          ipAddress: host,
          grade: cert ? 'B' : 'F',
          details: {
            certChains: [{
              certIds: [cert?.fingerprint256 || ''],
            }],
            protocols: [{
              id: 'TLS',
              name: 'TLS',
              version: protocol?.replace('TLSv', '') || '1.2',
              cipherSuite: cipher?.name || 'Unknown',
            }],
          },
        }],
      });
    });

    req.on('error', () => {
      resolve({
        host: host,
        error: 'Could not connect to server',
        localCheck: true,
        grade: 'F',
      });
    });

    req.on('timeout', () => { req.destroy(); resolve({ host, error: 'Timeout', localCheck: true }); });
    req.end();
  });

  res.json(localReport);
});

app.post('/api/security-headers', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  try {
    const response = await new Promise((resolve, reject) => {
      const options = {
        hostname: host,
        port: 443,
        path: '/',
        method: 'GET',
        timeout: 8000,
        rejectUnauthorized: false
      };

      const req = https.request(options, (res) => {
        resolve(res);
      });

      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
      req.end();
    });

    const headers = response.headers;
    const analysis = analyzeSecurityHeaders(headers);
    
    const httpVersion = response.socket?.getProtocol?.() || 'HTTP/1.1';
    const http2Support = response.httpVersion === '2.0' || httpVersion.includes('h2');
    
    res.json({
      domain: host,
      httpVersion: response.httpVersion,
      http2: http2Support,
      statusCode: response.statusCode,
      headers,
      analysis
    });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to fetch security headers' });
  }
});

app.post('/api/dnssec', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const resolver = new Resolver({ timeout: 5000, tries: 2 });

  try {
    const soaResult = await resolver.resolveSoa(host);
    
    const dnssecChecks = {
      present: false,
      checkedAt: new Date().toISOString(),
      domain: host,
      checks: {},
      issues: [],
      recommendations: []
    };
    
    try {
      const dnskeyRecords = await resolver.resolveDnsKeys(host);
      dnssecChecks.checks.dnskey = {
        present: dnskeyRecords.length > 0,
        count: dnskeyRecords.length,
        records: dnskeyRecords.map(r => ({
          flags: r.flags,
          protocol: r.protocol,
          algorithm: r.algorithm,
          keyTag: r.keyTag,
          keyType: r.flags === 256 ? 'KSK' : r.flags === 257 ? 'ZSK' : 'Unknown'
        }))
      };
      dnssecChecks.present = true;
    } catch (e) {
      dnssecChecks.checks.dnskey = { present: false, error: 'No DNSKEY records found' };
      dnssecChecks.issues.push('DNSKEY records not found - DNSSEC may not be configured');
    }
    
    try {
      const dsRecords = await resolver.resolveDs(host);
      dnssecChecks.checks.ds = {
        present: dsRecords.length > 0,
        count: dsRecords.length,
        records: dsRecords.map(r => ({
          keyTag: r.keyTag,
          algorithm: r.algorithm,
          digestType: r.digestType,
          digest: r.digest
        }))
      };
    } catch (e) {
      dnssecChecks.checks.ds = { present: false, error: 'No DS records found' };
      if (dnssecChecks.present) {
        dnssecChecks.issues.push('DNSSEC is signed but no DS records found at parent - delegation not secured');
      }
    }
    
    if (!dnssecChecks.present) {
      dnssecChecks.recommendations.push('Enable DNSSEC to ensure DNS response integrity');
      dnssecChecks.recommendations.push('Sign your zone at the registrar and publish DS records');
    } else {
      if (dnssecChecks.checks.ds?.present) {
        dnssecChecks.recommendations.push('DNSSEC is properly configured with chain of trust');
      }
    }
    
    dnssecChecks.rating = dnssecChecks.present && dnssecChecks.checks.ds?.present ? 'good' :
                          dnssecChecks.present ? 'incomplete' : 'not_configured';

    res.json(dnssecChecks);
  } catch (err) {
    res.status(500).json({ error: err.message || 'DNSSEC check failed' });
  }
});

app.post('/api/ocsp', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  let responded = false;
  const respond = (fn) => { if (!responded) { responded = true; fn(); } };

  const socket = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 10000 });
  socket.setTimeout(10000);

  socket.on('secureConnect', () => {
    try {
      const cert = socket.getPeerCertificate(true);
      socket.end();
      
      const result = {
        domain: host,
        checkedAt: new Date().toISOString(),
        certificate: {
          serialNumber: cert.serialNumber,
          issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
          validFrom: cert.valid_from,
          validTo: cert.valid_to
        },
        ocsp: {
          supported: false,
          responderURL: null,
          status: null
        },
        crl: {
          supported: false,
          distributionPoint: null
        },
        stapling: {
          supported: false,
          received: false,
          status: null
        },
        issues: [],
        rating: 'unknown'
      };
      
      if (cert.ocspURI) {
        result.ocsp.supported = true;
        result.ocsp.responderURL = cert.ocspURI;
      } else {
        result.issues.push('No OCSP responder URL in certificate');
      }
      
      if (cert.crlDistributionPoints) {
        result.crl.supported = true;
        result.crl.distributionPoint = cert.crlDistributionPoints;
      }
      
      if (cert.issuer?.O && cert.issuer.O.toLowerCase().includes('letsencrypt')) {
        result.ocsp.responderURL = `http://ocsp.int-x3.letsencrypt.org`;
        result.ocsp.supported = true;
      }
      
      if (cert.subject?.O && cert.subject.O.toLowerCase().includes('globalsign')) {
        result.ocsp.responderURL = `http://ocsp.globalsign.com`;
        result.ocsp.supported = true;
      }
      
      if (!result.ocsp.supported && !result.crl.supported) {
        result.issues.push('No revocation checking mechanism found');
        result.rating = 'warning';
      } else if (result.ocsp.supported) {
        result.rating = 'good';
      } else {
        result.rating = 'fair';
      }
      
      respond(() => res.json(result));
    } catch (err) {
      socket.end();
      respond(() => res.status(500).json({ error: err.message }));
    }
  });

  socket.on('error', (err) => respond(() => res.status(500).json({ error: err.message, code: err.code })));
  socket.on('timeout', () => { socket.destroy(); respond(() => res.status(504).json({ error: 'OCSP check timed out' })); });
});

app.post('/api/mta-sts', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const resolver = new Resolver({ timeout: 5000, tries: 2 });
  const result = {
    domain: host,
    checkedAt: new Date().toISOString(),
    mtaSts: { present: false, policy: null },
    tlsa: { present: false, records: [] },
    issues: [],
    rating: 'not_configured',
    recommendations: []
  };

  try {
    const mtaStsTxt = await resolver.resolveTxt(`_mta-sts.${host}`);
    if (mtaStsTxt && mtaStsTxt.length > 0) {
      const policy = mtaStsTxt[0].join('');
      result.mtaSts.present = true;
      result.mtaSts.raw = policy;
      
      const parsed = {};
      policy.split(';').forEach(part => {
        const [key, ...valueParts] = part.trim().split(':');
        if (key && valueParts.length) {
          parsed[key.trim()] = valueParts.join(':').trim();
        }
      });
      result.mtaSts.policy = parsed;
    }
  } catch (e) {
    result.mtaSts.present = false;
  }
  
  try {
    const mtaStsWellKnown = await fetch(`https://mta-sts.${host}/.well-known/mta-sts.txt`, { timeout: 5000 });
    if (mtaStsWellKnown.ok) {
      const text = await mtaStsWellKnown.text();
      const lines = text.split('\n');
      const policy = {};
      lines.forEach(line => {
        const colonIdx = line.indexOf(':');
        if (colonIdx > 0) {
          policy[line.substring(0, colonIdx).trim()] = line.substring(colonIdx + 1).trim();
        }
      });
      if (policy.version && policy.mode) {
        result.mtaSts.wellKnown = {
          present: true,
          policy
        };
      }
    }
  } catch (e) {
    result.mtaSts.wellKnown = { present: false, error: e.message };
  }
  
  try {
    const tlsaRecords = await resolver.resolveTlsa(`_443._tcp.${host}`);
    result.tlsa.present = true;
    result.tlsa.records = tlsaRecords.map(r => ({
      certificateUsage: r.certificateUsage,
      selector: r.selector,
      matchingType: r.matchingType,
      hash: r.certificateAssociationData
    }));
  } catch (e) {
    result.tlsa.present = false;
  }
  
  if (result.mtaSts.present && result.mtaSts.wellKnown?.present) {
    result.rating = 'good';
    result.recommendations.push('MTA-STS is properly configured');
  } else if (result.mtaSts.present) {
    result.rating = 'partial';
    result.recommendations.push('MTA-STS DNS record found but HTTPS endpoint not responding');
  } else if (result.tlsa.present) {
    result.rating = 'good';
    result.recommendations.push('DANE/TLSA records found - SMTP encryption verified');
  } else {
    result.issues.push('No MTA-STS or DANE/TLSA protection for SMTP');
    result.recommendations.push('Consider adding MTA-STS for SMTP encryption enforcement');
  }
  
  res.json(result);
});

app.post('/api/sshfp', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const resolver = new Resolver({ timeout: 5000, tries: 2 });

  try {
    const sshfpRecords = await resolver.resolveSshFp(host);
    const parsed = sshfpRecords.map(r => ({
      algorithm: r.algorithm,
      type: r.type,
      fingerprint: r.fpiration,
      algorithmName: ['RSA', 'DSA', 'ECDSA', 'Ed25519'][r.algorithm - 1] || 'Unknown',
      typeName: ['No Hash', 'SHA-1', 'SHA-256'][r.type] || 'Unknown'
    }));
    
    res.json({
      domain: host,
      present: true,
      count: sshfpRecords.length,
      records: parsed,
      rating: 'good',
      message: 'SSHFP records found - SSH server fingerprints can be verified via DNS'
    });
  } catch (err) {
    res.json({
      domain: host,
      present: false,
      count: 0,
      records: [],
      rating: 'not_configured',
      message: 'No SSHFP records found - SSH fingerprint verification via DNS not available',
      recommendations: ['Add SSHFP records if you use SSH with DNSSEC validation']
    });
  }
});

app.post('/api/redirect', heavyApiLimiter, async (req, res) => {
  const { domain, url } = req.body || {};
  if (!domain && !url) return res.status(400).json({ error: 'Domain or URL is required' });
  
  let targetUrl = url || `https://${normalizeDomain(domain)}`;
  if (!targetUrl.startsWith('http')) targetUrl = `https://${targetUrl}`;
  
  const chain = [];
  let currentUrl = targetUrl;
  let finalUrl = null;
  let totalTime = 0;
  const maxHops = 10;
  
  try {
    for (let hop = 0; hop < maxHops; hop++) {
      const startTime = Date.now();
      
      try {
        const response = await fetch(currentUrl, { 
          method: 'GET',
          redirect: 'manual',
          timeout: 8000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; HetOps-DNS/3.0)',
            'Accept': 'text/html,application/xhtml+xml'
          }
        });
        
        const duration = Date.now() - startTime;
        totalTime += duration;
        
        const redirectUrl = response.headers.get('location');
        
        chain.push({
          hop: hop + 1,
          url: currentUrl,
          statusCode: response.status,
          redirectTo: redirectUrl,
          durationMs: duration,
          headers: {
            'content-type': response.headers.get('content-type'),
            'server': response.headers.get('server'),
            'date': response.headers.get('date'),
            'cache-control': response.headers.get('cache-control'),
          }
        });
        
        if (response.status >= 300 && response.status < 400 && redirectUrl) {
          currentUrl = new URL(redirectUrl, currentUrl).href;
          continue;
        } else {
          finalUrl = currentUrl;
          break;
        }
      } catch (err) {
        chain.push({
          hop: hop + 1,
          url: currentUrl,
          error: err.message,
          durationMs: Date.now() - startTime
        });
        break;
      }
    }
    
    res.json({
      initialUrl: targetUrl,
      finalUrl,
      chain,
      totalHops: chain.length,
      totalTimeMs: totalTime,
      hasRedirects: chain.some(h => h.redirectTo),
      rating: chain.length > 5 ? 'warning' : 'good',
      message: chain.some(h => h.redirectTo) ? `Followed ${chain.filter(h => h.redirectTo).length} redirect(s)` : 'No redirects'
    });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Redirect trace failed' });
  }
});

app.post('/api/tech', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const TECH_PATTERNS = {
    'WordPress': [/wp-content/, /wp-includes/, /wordpress/i, /xmlrpc/],
    'Drupal': [/drupal/i, /sites\/default/, /modules\//],
    'Joomla': [/joomla/i, /components\//, /administrator/],
    'Magento': [/mage-/, /skin\/frontend/, /media\/catalog/],
    'Shopify': [/cdn.shopify/i, /shopify/i],
    'Wix': [/wixsite/i, /wix\.com/],
    'Squarespace': [/squarespace/i],
    'React': [/react/, /react-dom/, /_next\//],
    'Vue.js': [/vue/, /vuejs/],
    'Angular': [/angular/, /ng-/],
    'Next.js': [/__next/, /_next\//],
    'Nuxt.js': [/nuxt/, /__nuxt/],
    'Gatsby': [/gatsby/],
    'TailwindCSS': [/tailwind/i, /cdn.tailwindcss/],
    'Bootstrap': [/bootstrap/i, /cdn.jsdelivr.*bootstrap/],
    'jQuery': [/jquery/i],
    'Cloudflare': [/cloudflare/i, /cloudflaressl/],
    'CloudFront': [/cloudfront/, /d3n8a8pro7vhmx/],
    'AWS': [/amazonaws/, /s3\.amazonaws/],
    'Google Analytics': [/google-analytics/, /gtag/],
    'Google Tag Manager': [/googletagmanager/],
    'Facebook Pixel': [/facebook/, /fbevents/],
    'Hotjar': [/hotjar/],
    'Intercom': [/intercom/],
    'Stripe': [/stripe/],
    'PayPal': [/paypal/, /paypalobjects/],
    'HubSpot': [/hubspot/],
    'Mailchimp': [/mailchimp/, /mailchi/],
    'SendGrid': [/sendgrid/],
    'nginx': [/nginx/i],
    'Apache': [/apache/i],
    'Microsoft-IIS': [/microsoft-iis/i],
    'PHP': [/x-powered-by.*php/i, /php/i],
    'Node.js': [/x-powered-by.*express/i, /x-powered-by.*node/i],
    'Ruby on Rails': [/x-runtime.*rails/i, /rails/i],
    'Django': [/csrftoken/i, /django/i],
    'Laravel': [/laravel_session/i],
    'Python': [/x-powered-by.*python/i, /python/i],
    'ASP.NET': [/x-aspnet/i],
    'Vercel': [/vercel/i],
    'Netlify': [/netlify/i],
    'Firebase': [/firebase/i],
    'Heroku': [/heroku/i],
    'Akamai': [/akamai/i, /akamaized/],
    'Fastly': [/fastly/i, /fastlylb/],
    'Cloudflare': [/cloudflare/i, /cloudflaressl/],
  };

  const CDN_PATTERNS = {
    'Cloudflare': [/cloudflare\.com/, /cloudflaressl/, /cloudflare\.net/],
    'CloudFront': [/cloudfront\.net/, /d3n8a8pro7vhmx/, /d2ahvt9io4\.cloudfront/],
    'Fastly': [/fastly\.net/, /fastlylb/, /freetls\.fastly/],
    'Akamai': [/akamai\.com/, /akamaized\.net/, /edgesuite\.net/],
    'Azure CDN': [/azureedge\.net/, /azurewebsites\.net/],
    'Google Cloud CDN': [/googleusercontent\.com/, /gstatic\.com/],
    'Cloudflare': [/1\.1\.1\.1/, /cloudflare-original/],
    'CDN77': [/cdn77/, /cdnp1/],
    'KeyCDN': [/keycdn/, /kxcdn/],
    'BunnyCDN': [/bunnycdn/, / Bunny/],
  };

  const SECURITY_PATTERNS = {
    'reCAPTCHA': [/recaptcha/, /google.*recaptcha/],
    'hCaptcha': [/hcaptcha/, /hscript/],
    'Cloudflare Bot Management': [/cf-bot-protection/, /cloudflare/],
    'AWS WAF': [/aws-waf/, /awswaf/],
    'Imperva': [/imperva/, /incapsula/],
    'Sucuri': [/sucuri/, /cloudproxy/],
    'SiteLock': [/sitelock/, /sitelock/],
    'DDoS Protection': [/ddos-protection/, /ddosprotect/],
  };

  try {
    const response = await new Promise((resolve, reject) => {
      const options = {
        hostname: host,
        port: 443,
        path: '/',
        method: 'GET',
        timeout: 8000,
        rejectUnauthorized: false
      };
      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve({ headers: res.headers, body: data.substring(0, 50000), statusCode: res.statusCode }));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
      req.end();
    });

    const { headers, body } = response;
    const content = (JSON.stringify(headers) + ' ' + body).toLowerCase();
    
    const detected = {
      cms: [],
      frameworks: [],
      javascript: [],
      hosting: [],
      analytics: [],
      cdn: [],
      security: [],
      servers: [],
      other: []
    };

    for (const [name, patterns] of Object.entries(TECH_PATTERNS)) {
      if (patterns.some(p => p.test(content))) {
        if (['WordPress', 'Drupal', 'Joomla', 'Magento', 'Shopify', 'Wix', 'Squarespace'].includes(name)) {
          detected.cms.push(name);
        } else if (['React', 'Vue.js', 'Angular', 'Next.js', 'Nuxt.js', 'Gatsby', 'TailwindCSS', 'Bootstrap', 'jQuery'].includes(name)) {
          detected.javascript.push(name);
        } else if (['Cloudflare', 'CloudFront', 'AWS', 'Vercel', 'Netlify', 'Firebase', 'Heroku', 'Akamai', 'Fastly'].includes(name)) {
          detected.hosting.push(name);
        } else if (['Google Analytics', 'Google Tag Manager', 'Facebook Pixel', 'Hotjar', 'Intercom', 'Stripe', 'PayPal', 'HubSpot', 'Mailchimp', 'SendGrid'].includes(name)) {
          detected.analytics.push(name);
        } else if (['nginx', 'Apache', 'Microsoft-IIS', 'PHP', 'Node.js', 'Ruby on Rails', 'Django', 'Laravel', 'Python', 'ASP.NET'].includes(name)) {
          detected.servers.push(name);
        } else {
          detected.frameworks.push(name);
        }
      }
    }

    for (const [name, patterns] of Object.entries(CDN_PATTERNS)) {
      if (patterns.some(p => p.test(content))) {
        detected.cdn.push(name);
      }
    }

    for (const [name, patterns] of Object.entries(SECURITY_PATTERNS)) {
      if (patterns.some(p => p.test(content))) {
        detected.security.push(name);
      }
    }

    const serverHeader = headers['server'] || '';
    if (serverHeader && !detected.servers.some(s => serverHeader.toLowerCase().includes(s.toLowerCase()))) {
      detected.servers.push(serverHeader);
    }

    res.json({
      domain: host,
      detected,
      headers: {
        server: headers['server'],
        xPoweredBy: headers['x-powered-by'],
        xAspNetVersion: headers['x-aspnet-version'],
        contentType: headers['content-type'],
        cacheControl: headers['cache-control'],
        via: headers['via'],
        vary: headers['vary'],
      },
      rating: detected.cms.length + detected.frameworks.length > 0 ? 'detected' : 'unknown',
      message: `${detected.cms.length + detected.frameworks.length} technology stack(s) detected`
    });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Technology detection failed' });
  }
});

app.post('/api/http', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const result = {
    domain: host,
    protocols: { http1: false, http2: false, http3: false, h3: false },
    compression: { gzip: false, brotli: false, deflate: false },
    features: {},
    timing: {},
    rating: 'unknown',
    issues: [],
    recommendations: []
  };

  try {
    const startTime = Date.now();
    const response = await new Promise((resolve, reject) => {
      const options = {
        hostname: host,
        port: 443,
        path: '/',
        method: 'GET',
        timeout: 10000,
        rejectUnauthorized: false
      };
      const req = https.request(options, (res) => {
        result.timing.ttfbMs = Date.now() - startTime;
        result.protocols.http2 = res.httpVersion === '2.0';
        result.statusCode = res.statusCode;
        result.headers = res.headers;
        
        const acceptEncoding = res.headers['accept-encoding'] || '';
        result.compression.gzip = acceptEncoding.includes('gzip');
        result.compression.deflate = acceptEncoding.includes('deflate');
        
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          result.contentLength = data.length;
          result.bodyHash = require('crypto').createHash('md5').update(data).digest('hex');
          resolve(res);
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
      req.end();
    });

    result.timing.totalMs = Date.now() - startTime;
    
    if (response.headers['content-encoding']) {
      const encoding = response.headers['content-encoding'].toLowerCase();
      result.compression.brotli = encoding.includes('br');
      result.compression.gzip = encoding.includes('gzip') || encoding.includes('deflate');
    }

    if (response.headers['strict-transport-security']) {
      result.features.hsts = true;
      const maxAge = response.headers['strict-transport-security'].match(/max-age=(\d+)/);
      if (maxAge && parseInt(maxAge[1]) >= 31536000) {
        result.features.hstsLongTerm = true;
      }
    }

    if (response.headers['content-security-policy']) {
      result.features.csp = true;
    }

    if (response.headers['x-frame-options']) {
      result.features.xFrameOptions = true;
    }

    if (response.headers['referrer-policy']) {
      result.features.referrerPolicy = true;
    }

    // HTTP/3 detection via Alt-Svc header
    const altSvc = response.headers['alt-svc'] || '';
    result.protocols.http3 = /h3[=\-"]/i.test(altSvc);
    if (result.protocols.http3) {
      const h3Match = altSvc.match(/h3[=\-"]([^";\s,]+)/i);
      result.protocols.http3Port = h3Match ? h3Match[1].replace(/[":]/g,'') : '443';
    }

    const httpsTest = await fetch(`http://${host}`, { method: 'HEAD', signal: AbortSignal.timeout(5000), redirect: 'follow' }).catch(() => null);
    result.httpAvailable = true;

    let score = 0;
    if (result.protocols.http3) score += 15; else if (result.protocols.http2) score += 10;
    if (result.protocols.http2) score += 10;
    if (result.compression.brotli) { score += 20; } else if (result.compression.gzip) { score += 10; }
    if (result.features.hsts) score += 20;
    if (result.features.hstsLongTerm) score += 5;
    if (result.features.csp) score += 15;
    if (result.features.xFrameOptions) score += 10;
    if (result.features.referrerPolicy) score += 10;

    result.score = Math.min(100, score);
    result.rating = result.score >= 80 ? 'excellent' : result.score >= 60 ? 'good' : result.score >= 40 ? 'fair' : 'poor';

    if (!result.protocols.http2) result.recommendations.push('Enable HTTP/2 for better performance');
    if (!result.protocols.http3) result.recommendations.push('Enable HTTP/3 (QUIC) for lower latency on repeat visits');
    if (!result.compression.brotli && !result.compression.gzip) result.recommendations.push('Enable compression (Brotli preferred over gzip)');
    if (!result.features.hsts) result.recommendations.push('Enable HSTS with long max-age');
    if (!result.features.csp) result.recommendations.push('Add Content Security Policy');

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message || 'HTTP analysis failed' });
  }
});

app.post('/api/mx-smtp', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const resolver = new Resolver({ timeout: 5000, tries: 2 });
  const result = {
    domain: host,
    checkedAt: new Date().toISOString(),
    mxServers: [],
    issues: [],
    rating: 'unknown',
    recommendations: []
  };

  try {
    const mxRecords = await resolver.resolveMx(host);
    
    if (!mxRecords || mxRecords.length === 0) {
      result.issues.push('No MX records found - email delivery may fail');
      result.recommendations.push('Configure MX records for email receiving');
      return res.json(result);
    }

    result.mxServers = await Promise.all(mxRecords.slice(0, 5).map(async (mx) => {
      const mxInfo = {
        host: mx.exchange,
        priority: mx.priority,
        ipv4: null,
        ipv6: null,
        smtp: { supported: false, banner: null, starttls: null, tls: null },
        issues: []
      };

      try {
        const addresses = await resolver.resolve4(mx.exchange);
        mxInfo.ipv4 = addresses[0];
      } catch (e) {}

      try {
        const addresses6 = await resolver.resolve6(mx.exchange);
        mxInfo.ipv6 = addresses6[0];
      } catch (e) {}

      try {
        const smtpSocket = await new Promise((resolve, reject) => {
          const socket = net.connect(25, mx.exchange, () => {
            resolve({ connected: true, socket });
          });
          socket.setTimeout(5000);
          socket.on('timeout', () => { socket.destroy(); reject(new Error('SMTP timeout')); });
          socket.on('error', reject);
        });

        mxInfo.smtp.supported = true;
        const banner = await new Promise(resolve => {
          let data = '';
          smtpSocket.socket.on('data', chunk => { data += chunk; if (data.includes('\n')) resolve(data); });
          setTimeout(() => resolve(data || ''), 3000);
        });
        mxInfo.smtp.banner = banner.trim().substring(0, 200);

        if (banner.includes('220')) {
          smtpSocket.socket.write('EHLO test\r\n');
          const ehloResponse = await new Promise(resolve => {
            let data = '';
            smtpSocket.socket.on('data', chunk => { data += chunk; if (data.includes('\r\n')) resolve(data); });
            setTimeout(() => resolve(data), 3000);
          });
          
          mxInfo.smtp.starttls = ehloResponse.includes('STARTTLS');
          mxInfo.smtp.tls = ehloResponse.includes('250-STARTTLS');
          
          if (ehloResponse.includes('SIZE')) mxInfo.smtp.maxSize = true;
          if (ehloResponse.includes('8BITMIME')) mxInfo.smtp.eightBitMime = true;
          if (ehloResponse.includes('PIPELINING')) mxInfo.smtp.pipelining = true;
        }

        smtpSocket.socket.end();
      } catch (e) {
        mxInfo.issues.push('SMTP connection failed: ' + e.message);
      }

      return mxInfo;
    }));

    const allHaveStarttls = result.mxServers.every(m => m.smtp.starttls);
    const allHaveIPv4 = result.mxServers.every(m => m.ipv4);
    const allHaveBanner = result.mxServers.every(m => m.smtp.banner);

    if (allHaveStarttls && allHaveIPv4) {
      result.rating = 'good';
      result.recommendations.push('All MX servers support STARTTLS');
    } else if (allHaveIPv4) {
      result.rating = 'fair';
      if (!allHaveStarttls) {
        result.issues.push('Some MX servers do not support STARTTLS');
        result.recommendations.push('Enable STARTTLS on mail servers for encrypted email transport');
      }
    } else {
      result.rating = 'warning';
      result.issues.push('Some MX servers could not be resolved');
    }

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message || 'MX/SMTP analysis failed' });
  }
});

app.post('/api/cookies', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const result = {
    domain: host,
    cookies: [],
    analysis: {
      secure: 0,
      httpOnly: 0,
      sameSite: 0,
      session: 0,
      thirdParty: 0
    },
    issues: [],
    recommendations: [],
    rating: 'unknown'
  };

  try {
    const response = await new Promise((resolve, reject) => {
      const options = {
        hostname: host,
        port: 443,
        path: '/',
        method: 'GET',
        timeout: 8000,
        rejectUnauthorized: false,
        headers: {
          'Cookie': ''
        }
      };
      const req = https.request(options, (res) => {
        resolve(res);
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
      req.end();
    });

    const setCookieHeaders = response.headers['set-cookie'] || [];
    if (!Array.isArray(setCookieHeaders)) {
      result.cookies = [setCookieHeaders].filter(Boolean);
    } else {
      result.cookies = setCookieHeaders;
    }

    const parsedCookies = result.cookies.map(cookieStr => {
      const parts = cookieStr.split(';').map(p => p.trim());
      const [nameValue, ...attributes] = parts;
      const [name, value] = nameValue.split('=');
      
      const cookie = {
        name: name?.trim(),
        value: value?.trim(),
        secure: false,
        httpOnly: false,
        sameSite: null,
        expires: null,
        maxAge: null,
        path: null,
        domain: null
      };

      attributes.forEach(attr => {
        const lower = attr.toLowerCase();
        if (lower === 'secure') cookie.secure = true;
        else if (lower === 'httponly') cookie.httpOnly = true;
        else if (lower.startsWith('samesite=')) cookie.sameSite = attr.split('=')[1]?.trim();
        else if (lower.startsWith('expires=')) cookie.expires = attr.split('=')[1]?.trim();
        else if (lower.startswith('max-age=')) cookie.maxAge = parseInt(attr.split('=')[1]);
        else if (lower.startsWith('path=')) cookie.path = attr.split('=')[1]?.trim();
        else if (lower.startsWith('domain=')) cookie.domain = attr.split('=')[1]?.trim();
      });

      return cookie;
    });

    result.parsedCookies = parsedCookies;

    parsedCookies.forEach(cookie => {
      if (cookie.secure) result.analysis.secure++;
      if (cookie.httpOnly) result.analysis.httpOnly++;
      if (cookie.sameSite) result.analysis.sameSite++;
      if (!cookie.expires && !cookie.maxAge) result.analysis.session++;
    });

    const allSecure = parsedCookies.every(c => c.secure);
    const allHttpOnly = parsedCookies.every(c => c.httpOnly);
    const allSameSite = parsedCookies.every(c => c.sameSite);

    if (parsedCookies.length === 0) {
      result.message = 'No cookies set on homepage';
    } else if (allSecure && allHttpOnly && allSameSite) {
      result.rating = 'excellent';
      result.message = 'All cookies have proper security attributes';
    } else if (allSecure) {
      result.rating = 'good';
    } else {
      result.rating = 'warning';
    }

    if (!allSecure) result.issues.push('Some cookies lack Secure flag');
    if (!allHttpOnly) result.issues.push('Some cookies lack HttpOnly flag');
    if (!allSameSite) result.issues.push('Some cookies lack SameSite attribute');
    if (result.analysis.session > 0) result.recommendations.push('Consider setting expiration on session cookies for better security');

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Cookie analysis failed' });
  }
});

app.post('/api/cors', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const result = {
    domain: host,
    cors: {
      enabled: false,
      origin: null,
      credentials: false,
      methods: [],
      headers: [],
      maxAge: null,
      exposedHeaders: []
    },
    analysis: {},
    issues: [],
    recommendations: [],
    rating: 'unknown'
  };

  try {
    const response = await new Promise((resolve, reject) => {
      const options = {
        hostname: host,
        port: 443,
        path: '/',
        method: 'GET',
        timeout: 8000,
        rejectUnauthorized: false
      };
      const req = https.request(options, (res) => {
        resolve(res);
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
      req.end();
    });

    const corsHeader = response.headers['access-control-allow-origin'];
    if (corsHeader) {
      result.cors.enabled = true;
      result.cors.origin = corsHeader;
      result.cors.credentials = response.headers['access-control-allow-credentials'] === 'true';
      
      const methods = response.headers['access-control-allow-methods'];
      if (methods) result.cors.methods = methods.split(',').map(m => m.trim());
      
      const headers = response.headers['access-control-allow-headers'];
      if (headers) result.cors.headers = headers.split(',').map(h => h.trim());
      
      const maxAge = response.headers['access-control-max-age'];
      if (maxAge) result.cors.maxAge = parseInt(maxAge);
      
      const exposedHeaders = response.headers['access-control-expose-headers'];
      if (exposedHeaders) result.cors.exposedHeaders = exposedHeaders.split(',').map(h => h.trim());
    }

    if (!result.cors.enabled) {
      result.rating = 'good';
      result.message = 'CORS not enabled - API is not cross-origin accessible';
    } else if (result.cors.origin === '*') {
      result.rating = 'warning';
      result.issues.push('CORS allows all origins (*) - potential security risk');
      result.recommendations.push('Restrict CORS to specific trusted origins instead of *');
    } else if (result.cors.origin) {
      result.rating = 'good';
      result.message = `CORS configured for specific origins: ${result.cors.origin}`;
    }

    if (result.cors.enabled && !result.cors.credentials && result.cors.origin !== '*') {
      result.recommendations.push('Consider enabling credentials if your API uses authentication');
    }

    if (result.cors.enabled && !result.cors.maxAge) {
      result.recommendations.push('Consider setting Access-Control-Max-Age for better performance');
    }

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message || 'CORS analysis failed' });
  }
});

app.post('/api/trace', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const resolver = new Resolver({ timeout: 5000, tries: 2 });
  const result = {
    domain: host,
    ipv4: null,
    ipv6: null,
    hasIPv4: false,
    hasIPv6: false,
    dualStack: false,
    ping: [],
    issues: [],
    recommendations: []
  };

  try {
    try {
      const ipv4Addresses = await resolver.resolve4(host);
      result.ipv4 = ipv4Addresses[0];
      result.hasIPv4 = true;
    } catch (e) {}
    
    try {
      const ipv6Addresses = await resolver.resolve6(host);
      result.ipv6 = ipv6Addresses[0];
      result.hasIPv6 = true;
    } catch (e) {}

    result.dualStack = result.hasIPv4 && result.hasIPv6;

    if (result.hasIPv4) {
      for (let i = 0; i < 3; i++) {
        const start = Date.now();
        try {
          const socket = new net.Socket();
          await new Promise((resolve, reject) => {
            socket.setTimeout(3000);
            socket.on('connect', resolve);
            socket.on('timeout', () => { socket.destroy(); reject(new Error('timeout')); });
            socket.on('error', reject);
            socket.connect(80, result.ipv4);
          });
          socket.destroy();
          result.ping.push({ ip: result.ipv4, time: Date.now() - start, success: true });
        } catch (e) {
          result.ping.push({ ip: result.ipv4, time: null, success: false, error: e.message });
        }
      }
    }

    if (result.dualStack) {
      result.rating = 'excellent';
      result.message = 'Domain supports both IPv4 and IPv6 (dual-stack)';
    } else if (result.hasIPv4) {
      result.rating = 'good';
      result.message = 'IPv4 only - consider adding IPv6 support';
      result.recommendations.push('Enable IPv6 for better connectivity and SEO');
    } else if (result.hasIPv6) {
      result.rating = 'good';
      result.message = 'IPv6 only';
    } else {
      result.rating = 'warning';
      result.issues.push('Could not resolve any IP addresses');
    }

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Trace/ping failed' });
  }
});

app.post('/api/robots', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const result = {
    domain: host,
    robots: { present: false, content: null, rules: [] },
    sitemap: { present: false, urls: [], location: null },
    issues: [],
    recommendations: []
  };

  try {
    try {
      const robotsResponse = await fetch(`https://${host}/robots.txt`, { timeout: 5000 });
      if (robotsResponse.ok) {
        const content = await robotsResponse.text();
        result.robots.present = true;
        result.robots.content = content;

        const lines = content.split('\n');
        let currentUserAgent = '*';
        let currentRule = null;

        lines.forEach(line => {
          line = line.trim();
          if (line.startsWith('#') || !line) return;
          
          const colonIdx = line.indexOf(':');
          if (colonIdx < 0) return;
          
          const key = line.substring(0, colonIdx).trim().toLowerCase();
          const value = line.substring(colonIdx + 1).trim();
          
          if (key === 'user-agent') {
            if (currentRule) result.robots.rules.push(currentRule);
            currentUserAgent = value;
            currentRule = { userAgent: currentUserAgent, allow: [], disallow: [], crawlDelay: null };
          } else if (currentRule) {
            if (key === 'allow') currentRule.allow.push(value);
            else if (key === 'disallow') currentRule.disallow.push(value);
            else if (key === 'crawl-delay') currentRule.crawlDelay = parseFloat(value);
          } else {
            if (key === 'sitemap') result.robots.sitemapLocation = value;
          }
        });
        
        if (currentRule) result.robots.rules.push(currentRule);
      }
    } catch (e) {
      result.robots.present = false;
    }

    try {
      const sitemapLocations = [
        `https://${host}/sitemap.xml`,
        `https://${host}/sitemap-index.xml`,
        result.robots.sitemapLocation
      ].filter(Boolean);

      for (const location of sitemapLocations) {
        const sitemapResponse = await fetch(location, { timeout: 5000 });
        if (sitemapResponse.ok) {
          const content = await sitemapResponse.text();
          result.sitemap.present = true;
          result.sitemap.location = location;
          
          const urlMatches = content.match(/<loc[^>]*>([^<]+)<\/loc>/gi) || [];
          result.sitemap.urls = urlMatches.slice(0, 50).map(m => {
            const match = m.match(/<loc[^>]*>([^<]+)<\/loc>/i);
            return match ? match[1] : null;
          }).filter(Boolean);
          
          result.sitemap.totalUrls = result.sitemap.urls.length;
          break;
        }
      }
    } catch (e) {
      result.sitemap.present = false;
    }

    if (!result.robots.present) {
      result.issues.push('No robots.txt found - search engines may crawl everything');
      result.recommendations.push('Add a robots.txt file to control search engine crawling');
    } else {
      const hasDisallowAdmin = result.robots.rules.some(r => 
        r.disallow.some(d => d.includes('/admin') || d.includes('/wp-admin') || d.includes('/api'))
      );
      if (!hasDisallowAdmin) {
        result.recommendations.push('Consider disallowing /admin, /wp-admin, and /api paths');
      }
    }

    if (!result.sitemap.present) {
      result.recommendations.push('Add a sitemap.xml for better SEO');
    }

    result.rating = result.robots.present && result.sitemap.present ? 'good' : 
                     result.robots.present ? 'fair' : 'warning';

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Robots/sitemap check failed' });
  }
});

app.post('/api/cert-transparency', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const result = {
    domain: host,
    checkedAt: new Date().toISOString(),
    subdomains: [],
    issues: [],
    rating: 'unknown'
  };

  try {
    const ctApiUrl = `https://crt.sh/?q=${encodeURIComponent('%.' + host)}&output=json&limit=100`;
    
    try {
      const ctResponse = await fetch(ctApiUrl, { signal: AbortSignal.timeout(10000) });
      if (ctResponse.ok) {
        const data = await ctResponse.json();
        
        const domains = new Set();
        data.forEach(cert => {
          if (cert.name_value) {
            cert.name_value.split('\n').forEach(name => {
              const cleanName = name.trim().toLowerCase();
              if (cleanName.endsWith('.' + host) || cleanName === host) {
                if (!cleanName.startsWith('*.')) {
                  const subdomain = cleanName.replace('.' + host, '');
                  if (subdomain !== host) {
                    domains.add(subdomain);
                  }
                }
              }
            });
          }
        });
        
        result.subdomains = [...domains].slice(0, 50);
        result.totalCertificates = data.length;
        result.uniqueSubdomains = result.subdomains.length;
        
        if (result.subdomains.length > 0) {
          result.rating = 'good';
          result.message = `Found ${result.subdomains.length} unique subdomains from Certificate Transparency logs`;
        } else {
          result.message = 'No additional subdomains found in CT logs';
        }
      }
    } catch (e) {
      result.issues.push('Could not fetch Certificate Transparency logs: ' + e.message);
    }

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Certificate Transparency lookup failed' });
  }
});

app.post('/api/email-security', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const resolver = new Resolver();

  const result = {
    domain: host,
    checkedAt: new Date().toISOString(),
    spf: { present: false, record: null, policy: null, mechanisms: [], issues: [], score: 0 },
    dmarc: { present: false, record: null, policy: null, subdomainPolicy: null, pct: 100, rua: null, ruf: null, adkim: 'r', aspf: 'r', issues: [], score: 0 },
    dkim: { present: false, selectors: [] },
    bimi: { present: false, record: null, logoUrl: null },
    overallScore: 0,
    rating: 'none',
    recommendations: [],
    issues: []
  };

  // SPF analysis
  try {
    const txt = await resolver.resolveTxt(host);
    const spfRecord = txt.find(r => r.join('').toLowerCase().startsWith('v=spf1'));
    if (spfRecord) {
      result.spf.present = true;
      result.spf.record = spfRecord.join('');
      const spfStr = result.spf.record;
      const lower = spfStr.toLowerCase();
      result.spf.mechanisms = spfStr.split(/\s+/).slice(1);

      if (lower.includes('+all')) {
        result.spf.policy = '+all';
        result.spf.issues.push('SPF uses +all — any server can send mail for this domain (extremely permissive)');
      } else if (lower.includes('-all')) {
        result.spf.policy = '-all';
      } else if (lower.includes('~all')) {
        result.spf.policy = '~all';
        result.spf.issues.push('SPF uses ~all (softfail) — failing mail is accepted but tagged; consider using -all');
      } else if (lower.includes('?all')) {
        result.spf.policy = '?all';
        result.spf.issues.push('SPF uses ?all (neutral) — no protection against spoofing');
      } else {
        result.spf.issues.push('SPF record has no final all mechanism — behavior is undefined');
      }

      const lookupCount = (result.spf.mechanisms.filter(m =>
        /^[+\-~?]?(include:|a[:/]?|mx[:/]?|redirect=|exists:)/i.test(m)
      )).length;
      if (lookupCount > 10) {
        result.spf.issues.push(`SPF exceeds 10 DNS lookups (found ~${lookupCount}) — some servers will reject mail`);
      }

      if (/\bptr\b/i.test(spfStr)) {
        result.spf.issues.push('SPF uses deprecated ptr mechanism — remove it');
      }

      result.spf.score = result.spf.issues.length === 0 && result.spf.policy === '-all' ? 100
        : result.spf.issues.length === 0 ? 85
        : result.spf.policy === '+all' ? 10 : 60;
    } else {
      result.spf.issues.push('No SPF record found');
      result.recommendations.push('Add SPF: "v=spf1 include:<your-mail-provider> -all"');
    }
  } catch (e) {
    if (!isExpectedDnsMiss(e)) result.spf.issues.push('SPF lookup failed: ' + e.message);
    else { result.spf.issues.push('No SPF record found'); result.recommendations.push('Add SPF: "v=spf1 include:<your-mail-provider> -all"'); }
  }

  // DMARC analysis
  try {
    const dmarcTxt = await resolver.resolveTxt(`_dmarc.${host}`);
    const dmarcRecord = dmarcTxt.find(r => r.join('').toLowerCase().startsWith('v=dmarc1'));
    if (dmarcRecord) {
      result.dmarc.present = true;
      result.dmarc.record = dmarcRecord.join('');
      const params = {};
      result.dmarc.record.split(';').forEach(part => {
        const eq = part.indexOf('=');
        if (eq !== -1) {
          const k = part.slice(0, eq).trim().toLowerCase();
          const v = part.slice(eq + 1).trim();
          if (k) params[k] = v;
        }
      });
      result.dmarc.policy = params.p || null;
      result.dmarc.subdomainPolicy = params.sp || null;
      result.dmarc.pct = params.pct ? parseInt(params.pct, 10) : 100;
      result.dmarc.rua = params.rua || null;
      result.dmarc.ruf = params.ruf || null;
      result.dmarc.adkim = params.adkim || 'r';
      result.dmarc.aspf = params.aspf || 'r';

      if (result.dmarc.policy === 'none') {
        result.dmarc.issues.push('DMARC policy is "none" — monitoring only, no enforcement');
        result.recommendations.push('Change DMARC p=none to p=quarantine or p=reject to actively protect against phishing');
      } else if (result.dmarc.policy === 'quarantine' && result.dmarc.pct < 100) {
        result.dmarc.issues.push(`DMARC policy applies to only ${result.dmarc.pct}% of messages — increase pct to 100`);
      }

      if (!result.dmarc.rua) {
        result.dmarc.issues.push('No aggregate report address (rua=) — DMARC failures are not monitored');
        result.recommendations.push('Add rua= to DMARC record to receive aggregate reports');
      }

      result.dmarc.score = result.dmarc.policy === 'reject' && result.dmarc.pct === 100 ? 100
        : result.dmarc.policy === 'reject' ? 85
        : result.dmarc.policy === 'quarantine' && result.dmarc.pct === 100 ? 80
        : result.dmarc.policy === 'quarantine' ? 65
        : result.dmarc.policy === 'none' ? 30 : 0;
    } else {
      result.dmarc.issues.push('No DMARC record found');
      result.recommendations.push(`Add DMARC: "_dmarc.${host} TXT v=DMARC1; p=quarantine; rua=mailto:dmarc@${host}"`);
    }
  } catch (e) {
    if (!isExpectedDnsMiss(e)) result.dmarc.issues.push('DMARC lookup failed: ' + e.message);
    else {
      result.dmarc.issues.push('No DMARC record found');
      result.recommendations.push(`Add DMARC: "_dmarc.${host} TXT v=DMARC1; p=quarantine; rua=mailto:dmarc@${host}"`);
    }
  }

  // DKIM discovery (common selectors)
  const dkimSelectors = ['default', 'google', 'mail', 'dkim', 'k1', 'k2', 's1', 's2', 'email', 'selector1', 'selector2', 'mimecast', 'sendgrid', 'mailchimp', 'amazonses'];
  const dkimFound = [];
  await Promise.all(dkimSelectors.map(async (sel) => {
    try {
      const records = await resolver.resolveTxt(`${sel}._domainkey.${host}`);
      if (records.some(r => r.join('').toLowerCase().includes('v=dkim1'))) {
        dkimFound.push(sel);
      }
    } catch (e) {}
  }));
  if (dkimFound.length > 0) {
    result.dkim.present = true;
    result.dkim.selectors = dkimFound;
  } else {
    result.issues.push('No DKIM public keys found for common selectors');
    result.recommendations.push('Ensure DKIM signing is configured and the public key is published at <selector>._domainkey.' + host);
  }

  // BIMI check
  try {
    const bimiTxt = await resolver.resolveTxt(`default._bimi.${host}`);
    const bimiRecord = bimiTxt.find(r => r.join('').toLowerCase().startsWith('v=bimi1'));
    if (bimiRecord) {
      result.bimi.present = true;
      result.bimi.record = bimiRecord.join('');
      const lMatch = result.bimi.record.match(/l=([^;]+)/i);
      if (lMatch) result.bimi.logoUrl = lMatch[1].trim();
    }
  } catch (e) {}

  // Overall score
  let pts = 0, max = 0;
  max += 100; pts += result.spf.present ? result.spf.score : 0;
  max += 100; pts += result.dmarc.present ? result.dmarc.score : 0;
  max += 100; pts += result.dkim.present ? 100 : 0;
  if (result.bimi.present) { max += 50; pts += 50; }

  result.overallScore = max > 0 ? Math.round((pts / max) * 100) : 0;
  result.rating = result.overallScore >= 85 ? 'strong' : result.overallScore >= 65 ? 'good' : result.overallScore >= 40 ? 'fair' : 'weak';

  res.json(result);
});

app.post('/api/propagation', heavyApiLimiter, async (req, res) => {
  const { domain, type = 'A' } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const recordType = String(type).toUpperCase();
  if (!recordTypes.includes(recordType)) return res.status(400).json({ error: 'Invalid record type' });

  const results = await Promise.all(PROPAGATION_RESOLVERS.map(async (srv) => {
    const resolver = new Resolver({ timeout: 4000, tries: 1 });
    resolver.setServers([srv.ip]);
    const start = Date.now();
    try {
      const records = await lookupRecord(resolver, host, recordType);
      return { ...srv, status: 'ok', records, durationMs: Date.now() - start };
    } catch (err) {
      return { ...srv, status: 'error', error: err.message, records: [], durationMs: Date.now() - start };
    }
  }));

  res.json({ domain: host, type: recordType, results });
});

// ── Subdomain Takeover Detector ───────────────────────────────
const TAKEOVER_SERVICES = [
  { service: 'GitHub Pages',  pattern: /\.github\.io$/i,              fingerprint: "there isn't a github pages site here" },
  { service: 'Heroku',        pattern: /\.herokuapp\.com$/i,          fingerprint: 'no such app' },
  { service: 'Fastly',        pattern: /\.fastly\.net$|\.fastlylb\.net$/i, fingerprint: 'fastly error: unknown domain' },
  { service: 'Shopify',       pattern: /\.myshopify\.com$/i,          fingerprint: 'sorry, this shop is currently unavailable' },
  { service: 'Ghost',         pattern: /\.ghost\.io$/i,               fingerprint: 'the thing you were looking for is no longer here' },
  { service: 'Netlify',       pattern: /\.netlify\.app$|\.netlify\.com$/i, fingerprint: 'not found - request id' },
  { service: 'AWS S3',        pattern: /\.s3\.amazonaws\.com$|\.s3-website/i, fingerprint: 'nosuchbucket' },
  { service: 'Azure',         pattern: /\.azurewebsites\.net$/i,      fingerprint: '404 web site not found' },
  { service: 'Surge.sh',      pattern: /\.surge\.sh$/i,               fingerprint: 'project not found' },
  { service: 'Vercel',        pattern: /\.vercel\.app$/i,             fingerprint: 'the deployment could not be found' },
  { service: 'HubSpot',       pattern: /\.hs-sites\.com$/i,           fingerprint: 'domain not configured' },
  { service: 'Zendesk',       pattern: /\.zendesk\.com$/i,            fingerprint: 'help center closed' },
  { service: 'Squarespace',   pattern: /\.squarespace\.com$/i,        fingerprint: 'no such account' },
  { service: 'Webflow',       pattern: /\.webflow\.io$/i,             fingerprint: "the page you are looking for doesn't exist" },
  { service: 'Firebase',      pattern: /\.firebaseapp\.com$|\.web\.app$/i, fingerprint: 'the specified bucket does not exist' },
  { service: 'Pantheon',      pattern: /\.pantheonsite\.io$/i,        fingerprint: 'the gods are wise' },
  { service: 'Tumblr',        pattern: /\.tumblr\.com$/i,             fingerprint: "there's nothing here" },
  { service: 'Bitbucket',     pattern: /\.bitbucket\.io$/i,           fingerprint: 'repository not found' },
];

const TAKEOVER_SUBDOMAINS = ['www','mail','ftp','api','dev','staging','app','beta','docs','blog','admin','portal','cdn','assets','static','help','support','status'];

app.post('/api/subdomain-takeover', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string') return res.status(400).json({ error: 'Domain required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain' });

  const resolver = new Resolver({ timeout: 3000, tries: 1 });
  resolver.setServers(['8.8.8.8', '1.1.1.1']);

  const cnameResults = [];
  await Promise.allSettled(TAKEOVER_SUBDOMAINS.map(async (sub) => {
    const fqdn = `${sub}.${host}`;
    try {
      const cnames = await resolver.resolveCname(fqdn);
      const cname = cnames[0];
      if (!cname) return;
      const svc = TAKEOVER_SERVICES.find(s => s.pattern.test(cname));
      const entry = { subdomain: fqdn, cname, service: svc?.service || null, vulnerable: false, checked: !!svc };
      if (svc) {
        try {
          const r = await fetch(`https://${fqdn}`, {
            signal: AbortSignal.timeout(5000), redirect: 'follow',
            headers: { 'User-Agent': 'HetOps-DNS-Scanner/5.0' }
          });
          const body = (await r.text()).toLowerCase();
          entry.statusCode = r.status;
          entry.vulnerable = body.includes(svc.fingerprint) || r.status === 404;
          if (entry.vulnerable) entry.fingerprintMatch = svc.fingerprint;
        } catch (e) { entry.fetchError = true; }
      }
      cnameResults.push(entry);
    } catch (e) {}
  }));

  const vulnerabilities = cnameResults.filter(r => r.vulnerable);
  res.json({ domain: host, cnamesFound: cnameResults.length, vulnerabilities, results: cnameResults, vulnerable: vulnerabilities.length > 0 });
});

// ── HSTS Preload ───────────────────────────────────────────────
app.post('/api/hsts-preload', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain' });

  let preloadStatus = 'unknown';
  let hstsHeader = null, maxAge = null, includeSubDomains = false, preloadDirective = false;

  try {
    const pr = await fetch(`https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(host)}`, {
      signal: AbortSignal.timeout(8000), headers: { 'User-Agent': 'HetOps-DNS-Scanner/5.0' }
    });
    if (pr.ok) { const d = await pr.json(); preloadStatus = d.status || 'unknown'; }
  } catch (e) {}

  try {
    const sr = await fetch(`https://${host}`, {
      signal: AbortSignal.timeout(6000), redirect: 'manual',
      headers: { 'User-Agent': 'HetOps-DNS-Scanner/5.0' }
    });
    hstsHeader = sr.headers.get('strict-transport-security');
    if (hstsHeader) {
      const m = hstsHeader.match(/max-age=(\d+)/i);
      if (m) maxAge = parseInt(m[1]);
      includeSubDomains = /includeSubDomains/i.test(hstsHeader);
      preloadDirective = /preload/i.test(hstsHeader);
    }
  } catch (e) {}

  const eligible = !!(maxAge && maxAge >= 31536000 && includeSubDomains && preloadDirective);
  res.json({
    domain: host, preloadStatus, hstsHeader, maxAge,
    maxAgeDays: maxAge ? Math.floor(maxAge / 86400) : null,
    includeSubDomains, preloadDirective, eligible,
    onPreloadList: preloadStatus === 'preloaded',
    pending: preloadStatus === 'pending',
  });
});

// ── CSP Analyzer ───────────────────────────────────────────────
app.post('/api/csp-analyzer', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain' });

  try {
    const r = await fetch(`https://${host}`, {
      signal: AbortSignal.timeout(8000), redirect: 'follow',
      headers: { 'User-Agent': 'Mozilla/5.0 HetOps-DNS-Scanner/5.0' }
    });
    const cspFull = r.headers.get('content-security-policy');
    const cspRO   = r.headers.get('content-security-policy-report-only');
    const cspHeader = cspFull || cspRO;
    const isReportOnly = !cspFull && !!cspRO;

    if (!cspHeader) {
      return res.json({ domain: host, present: false, grade: 'F', score: 0, issues: ['No Content-Security-Policy header found'], warnings: [], directives: {} });
    }

    const directives = {};
    for (const part of cspHeader.split(';').map(p => p.trim()).filter(Boolean)) {
      const tokens = part.split(/\s+/);
      directives[tokens[0].toLowerCase()] = tokens.slice(1);
    }

    const issues = [], warnings = [];
    let score = 100;
    const capScore = (cap) => { if (score > cap) score = cap; };

    const def       = directives['default-src'] || [];
    const scriptSrc = directives['script-src'] || def;
    const styleSrc  = directives['style-src']  || def;

    if (!directives['default-src'])                      { issues.push("Missing default-src directive"); score -= 15; }
    if (scriptSrc.includes("'unsafe-inline'"))           { issues.push("script-src allows 'unsafe-inline' — XSS risk"); score -= 25; }
    if (scriptSrc.includes("'unsafe-eval'"))             { issues.push("script-src allows 'unsafe-eval' — code injection risk"); score -= 20; }
    if (scriptSrc.includes('*') || def.includes('*'))   { issues.push("Wildcard (*) in script/default-src — overly permissive"); capScore(40); }
    if (styleSrc.includes("'unsafe-inline'"))            { warnings.push("style-src allows 'unsafe-inline'"); score -= 5; }
    if (!directives['frame-ancestors'])                  { warnings.push("No frame-ancestors directive (prevents clickjacking)"); score -= 5; }
    if (!directives['base-uri'])                         { warnings.push("No base-uri directive"); score -= 3; }
    if (!directives['form-action'])                      { warnings.push("No form-action directive"); score -= 3; }
    if (isReportOnly)                                    { warnings.push("CSP is report-only — not enforced in production"); score -= 10; }

    score = Math.max(0, Math.min(100, score));
    const grade = score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

    res.json({
      domain: host, present: true, isReportOnly, grade, score,
      directives, directiveCount: Object.keys(directives).length,
      hasNonce: scriptSrc.some(v => v.startsWith("'nonce-")),
      hasHash: scriptSrc.some(v => /^'sha(256|384|512)-/.test(v)),
      hasStrictDynamic: scriptSrc.includes("'strict-dynamic'"),
      issues, warnings, rawHeader: cspHeader,
    });
  } catch (e) {
    res.json({ domain: host, error: e.message });
  }
});

// ── Typosquat Detector ─────────────────────────────────────────
function generateTypos(domain) {
  const dotIdx = domain.indexOf('.');
  if (dotIdx < 1) return [];
  const name = domain.slice(0, dotIdx);
  const tld  = domain.slice(dotIdx + 1);
  const typos = new Set();

  for (let i = 0; i < name.length; i++)
    typos.add(name.slice(0, i) + name.slice(i + 1) + '.' + tld);

  for (let i = 0; i < name.length; i++)
    typos.add(name.slice(0, i) + name[i] + name[i] + name.slice(i + 1) + '.' + tld);

  for (let i = 0; i < name.length - 1; i++) {
    const t = name.split(''); [t[i], t[i + 1]] = [t[i + 1], t[i]];
    typos.add(t.join('') + '.' + tld);
  }

  for (const [ch, sub] of [['a','4'],['e','3'],['i','1'],['o','0'],['s','5'],['l','1']])
    if (name.includes(ch)) typos.add(name.replaceAll(ch, sub) + '.' + tld);

  for (const t of ['com','net','org','io','co','app','dev']) if (t !== tld) typos.add(name + '.' + t);

  typos.delete(domain);
  return [...typos].filter(d => /^[a-z0-9][a-z0-9.-]{0,61}[a-z0-9]\.[a-z]{2,}$/.test(d)).slice(0, 35);
}

app.post('/api/typosquat', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain' });

  const variants = generateTypos(host);
  const resolver = new Resolver({ timeout: 2000, tries: 1 });
  resolver.setServers(['8.8.8.8', '1.1.1.1']);

  const settled = await Promise.allSettled(variants.map(async (v) => {
    try {
      const ips = await resolver.resolve4(v);
      return { domain: v, registered: true, ips };
    } catch (e) {
      return { domain: v, registered: false };
    }
  }));

  const results = settled.map((r, i) => r.status === 'fulfilled' ? r.value : { domain: variants[i], registered: false });
  const registered = results.filter(r => r.registered);
  res.json({ domain: host, total: variants.length, registered: registered.length, results });
});

// ── IPv6 Reachability ──────────────────────────────────────────
app.post('/api/ipv6', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain' });

  const resolver = new Resolver({ timeout: 4000, tries: 2 });
  resolver.setServers(['8.8.8.8', '1.1.1.1']);

  let ipv4 = [], ipv6 = [];
  try { ipv4 = await resolver.resolve4(host); } catch (e) {}
  try { ipv6 = await resolver.resolve6(host); } catch (e) {}

  function tryTls(address, family) {
    return new Promise(resolve => {
      const opts = { host: address, port: 443, servername: host, timeout: 5000, rejectUnauthorized: false };
      if (family === 6) opts.family = 6;
      const sock = tls.connect(opts, () => {
        const proto = sock.getProtocol();
        const authErr = sock.authorizationError;
        sock.destroy();
        resolve({ success: true, protocol: proto, certValid: !authErr });
      });
      sock.on('error', e => resolve({ success: false, error: e.message }));
      sock.on('timeout', () => { sock.destroy(); resolve({ success: false, error: 'timeout' }); });
    });
  }

  const [tlsV4, tlsV6] = await Promise.all([
    ipv4.length > 0 ? tryTls(ipv4[0], 4) : Promise.resolve(null),
    ipv6.length > 0 ? tryTls(ipv6[0], 6) : Promise.resolve(null),
  ]);

  const dualStack = ipv4.length > 0 && ipv6.length > 0;
  let score = 0;
  if (ipv6.length > 0) score += 40;
  if (dualStack) score += 20;
  if (tlsV6?.success) score += 30;
  if (tlsV4?.success && tlsV6?.success) score += 10;

  res.json({ domain: host, ipv4, ipv6, dualStack, ipv6Enabled: ipv6.length > 0, tlsV4, tlsV6, score });
});

// ── DNSSEC Chain Validator ─────────────────────────────────────
app.post('/api/dnssec-chain', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain' });

  const mkRes = (servers) => { const r = new Resolver({ timeout: 5000, tries: 2 }); r.setServers(servers); return r; };
  const rMain = mkRes(['8.8.8.8', '1.1.1.1']);
  const rGoogle = mkRes(['8.8.8.8']);
  const rCF = mkRes(['1.1.1.1']);

  async function hasRecord(resolver, name, type) {
    try { const r = await resolver.resolve(name, type); return !!(r && r.length > 0); } catch (e) { return false; }
  }

  const chain = [], issues = [];

  const hasDNSKEY = await hasRecord(rMain, host, 'DNSKEY');
  chain.push({ step: 'DNSKEY', domain: host, present: hasDNSKEY, desc: 'Zone signing key(s) at zone apex' });
  if (!hasDNSKEY) issues.push('No DNSKEY records — DNSSEC not configured');

  const hasDS = await hasRecord(rMain, host, 'DS');
  const parentZone = host.split('.').slice(1).join('.');
  chain.push({ step: 'DS', domain: `${host} at ${parentZone}`, present: hasDS, desc: 'Delegation Signer record links parent zone to child' });
  if (hasDNSKEY && !hasDS) issues.push('DNSKEY exists but no DS at parent — chain of trust is broken');

  const hasRRSIG = await hasRecord(rMain, host, 'RRSIG');
  chain.push({ step: 'RRSIG', domain: host, present: hasRRSIG, desc: 'Resource Record Signatures (records are signed)' });
  if (hasDNSKEY && !hasRRSIG) issues.push('DNSKEY present but no RRSIG — zone records may not be signed');

  const hasNSEC = await hasRecord(rMain, host, 'NSEC3') || await hasRecord(rMain, host, 'NSEC');
  chain.push({ step: 'NSEC/NSEC3', domain: host, present: hasNSEC, desc: 'Authenticated denial of existence' });

  const [g, c] = await Promise.all([hasRecord(rGoogle, host, 'DNSKEY'), hasRecord(rCF, host, 'DNSKEY')]);
  const consistent = g === c;
  chain.push({ step: 'Consistency', domain: '8.8.8.8 vs 1.1.1.1', present: consistent, desc: 'DNSSEC data matches across Google and Cloudflare' });
  if (!consistent) issues.push('DNSSEC inconsistency between resolvers — possible misconfiguration');

  const signed = hasDNSKEY && hasDS && hasRRSIG;
  const valid  = signed && consistent && issues.length === 0;
  const status = valid ? 'valid' : signed ? 'partial' : hasDNSKEY ? 'incomplete' : 'unsigned';

  res.json({ domain: host, signed, valid, status, chain, issues,
    statusMessage: valid ? 'Full DNSSEC chain validated' : signed ? 'DNSSEC configured with issues' : hasDNSKEY ? 'DNSSEC partially configured' : 'DNSSEC not enabled' });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'HetOps DNS Intelligence',
    version: '6.0.0',
    features: [
      'batchLookup', 'resolverProfiles', 'securityInsights', 'timingMetrics',
      'authoritativeComparison', 'subdomainDiscovery', 'cnameChainTracing',
      'sslAnalysis', 'sslChainValidation', 'sslCipherAnalysis', 'sslOcspCheck',
      'securityHeadersAnalysis', 'dnssecValidation', 'dnssecChainValidation',
      'mtaStsCheck', 'sshfpLookup', 'globalPropagation', 'blacklistCheck',
      'geoipLookup', 'portScanning', 'redirectChain', 'technologyFingerprint',
      'httpAnalysis', 'mxSmtpAnalysis', 'cookieAnalysis', 'corsAnalysis',
      'ipv4Ipv6Check', 'ipv6Reachability', 'robotsSitemap', 'certTransparency',
      'emailSecurityAnalysis', 'spfAnalysis', 'dmarcAnalysis', 'dkimDiscovery',
      'bimiCheck', 'subdomainTakeover', 'hstsPreload', 'cspAnalyzer',
      'typosquatDetection'
    ]
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`DNS Lookup tool running on port ${PORT}`);
});
