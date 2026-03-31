const express = require('express');
const dns = require('node:dns');
const { Resolver } = require('node:dns').promises;
const path = require('node:path');
const net = require('node:net');
const tls = require('node:tls');
const https = require('node:https');
const whois = require('whois');
const rateLimit = require('express-rate-limit');

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
        const rdapReq = await fetch(`https://rdap.org/domain/${host}`, { headers: { 'Accept': 'application/rdap+json' } });
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
      return res.status(502).json({ error: `GeoIP provider returned HTTP ${response.statusCode}` });
    }

    let data = '';
    response.on('data', (chunk) => data += chunk);
    response.on('end', () => {
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
    res.status(500).json({ error: err.message || 'GeoIP fetch failed' });
  });

  geoReq.on('timeout', () => {
    geoReq.destroy();
    res.status(504).json({ error: 'GeoIP request timed out' });
  });
});

app.post('/api/blacklist-check', heavyApiLimiter, async (req, res) => {
  const { domain } = req.body;
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  const blacklists = ['zen.spamhaus.org', 'b.barracudacentral.org', 'bl.spamcop.net'];
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

app.post('/api/ssl', heavyApiLimiter, (req, res) => {
  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string' || domain.length > 256) return res.status(400).json({ error: 'Valid domain is required' });
  const host = normalizeDomain(domain);
  if (!host) return res.status(400).json({ error: 'Invalid domain format' });

  let responded = false;
  const respond = (fn) => { if (!responded) { responded = true; fn(); } };

  const socket = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false });
  socket.setTimeout(10000);

  socket.on('secureConnect', () => {
    try {
      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      const authorized = socket.authorized;
      const authError = socket.authorizationError;
      socket.end();

      const now = new Date();
      const validTo = new Date(cert.valid_to);
      const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

      const subjectAltNames = cert.subjectaltname
        ? cert.subjectaltname.split(', ').filter(s => s.startsWith('DNS:')).map(s => s.replace('DNS:', ''))
        : [];

      respond(() => res.json({
        domain: host,
        valid: authorized,
        authorizationError: authError || null,
        subject: cert.subject || {},
        issuer: cert.issuer || {},
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        daysRemaining,
        serialNumber: cert.serialNumber,
        fingerprint: cert.fingerprint,
        fingerprint256: cert.fingerprint256,
        protocol,
        cipher: cipher ? { name: cipher.name, version: cipher.version, standardName: cipher.standardName } : null,
        subjectAltNames,
        keyBits: cert.bits,
      }));
    } catch (err) {
      socket.end();
      respond(() => res.status(500).json({ error: err.message }));
    }
  });

  socket.on('error', (err) => respond(() => res.status(500).json({ error: err.message, code: err.code })));
  socket.on('timeout', () => { socket.destroy(); respond(() => res.status(504).json({ error: 'SSL connection timed out' })); });
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

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'HetOps DNS Intelligence',
    version: '2.0.0',
    features: ['batchLookup', 'resolverProfiles', 'securityInsights', 'timingMetrics', 'authoritativeComparison', 'subdomainDiscovery', 'cnameChainTracing', 'sslAnalysis', 'globalPropagation']
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`DNS Lookup tool running on port ${PORT}`);
});
