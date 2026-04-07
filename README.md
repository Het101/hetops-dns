# HetOps DNS Intelligence — dns.hetops.dev

A comprehensive domain intelligence platform that replaces multiple tools including SSL Labs, SSL Checker, Wappalyzer, MXToolbox, and more. Built for security professionals, developers, and DevOps engineers.

## Features

### SSL/TLS Analysis (SSL Labs-style)
- **Protocol Support Detection** - TLS 1.0, 1.1, 1.2, 1.3 with version-specific cipher detection
- **SSL Labs-Style Grading** - A+ to F with score 0-100
- **Cipher Suite Analysis** - Classification (good/warning/critical) with PFS detection
- **Certificate Chain Validation** - Full chain (leaf, intermediate, root) with trust chain verification
- **Vulnerability Detection** - BEAST, POODLE, SWEET32, LOGJAM, DROWN, FREAK, CRIME, BREACH, ROBOT
- **Perfect Forward Secrecy (PFS)** - ECDHE/DHE/CHACHA20 detection
- **Client Simulation** - Test compatibility with Firefox, Chrome, Safari, Edge, Android, Java, IE
- **Days Until Expiration** - Certificate expiry tracking with warnings
- **Subject Alternative Names (SAN)** - All valid domains on certificate
- **OCSP Stapling Detection** - Server-side stapling capability

### Security Headers Analysis
- **HSTS** (HTTP Strict Transport Security) - HTTPS enforcement with preload status
- **CSP** (Content Security Policy) - XSS and injection protection analysis
- **X-Frame-Options** - Clickjacking protection
- **X-Content-Type-Options** - MIME sniffing prevention
- **Referrer-Policy** - Referrer information control
- **Permissions-Policy** - Browser feature restrictions
- **Cache-Control** - Caching directives analysis
- **Server Header Analysis** - Information leakage detection
- **Header Score** - 0-100 rating with hardening recommendations

### Certificate Revocation & Trust
- **OCSP Status Check** - Online Certificate Status Protocol availability
- **CRL Distribution Points** - Certificate Revocation List endpoints
- **OCSP Stapling Detection** - Server-side stapling capability
- **Certificate Transparency Lookup** - Subdomain discovery from CT logs

### DNSSEC Validation
- **DNSKEY Records** - Zone signing key verification (KSK/ZSK)
- **DS Records** - Delegation Signer validation
- **Chain of Trust Analysis** - DNSSEC chain verification
- **Configuration Recommendations** - Hardening suggestions

### Email Security
- **MTA-STS** - SMTP strict transport security policy analysis
- **DANE/TLSA** - DNS-based TLS authentication for SMTP
- **Policy Mode Detection** - enforce/testing/none status
- **MX Records Analysis** - Mail exchanger detection
- **STARTTLS Support** - SMTP encryption capability detection

### Technology Fingerprinting (Wappalyzer-style)
Detects 40+ technologies including:
- **CMS**: WordPress, Drupal, Joomla, Magento, Shopify, Ghost, Squarespace
- **Frameworks**: React, Vue, Angular, Next.js, Nuxt, Svelte, Gatsby
- **JavaScript**: jQuery, Express, Node.js, TypeScript, Webpack
- **Servers**: Apache, Nginx, IIS, Cloudflare, Varnish, OpenResty
- **CDNs**: Cloudflare, AWS CloudFront, Fastly, Akamai, Google Cloud CDN
- **Analytics**: Google Analytics, Plausible, Mixpanel, Segment
- **Security**: Cloudflare, Sucuri, Wordfence, reCAPTCHA
- **Hosting**: AWS, Azure, Google Cloud, Vercel, Netlify, Heroku

### HTTP & Network Analysis
- **HTTP/2 Support** - HTTP/2 protocol detection
- **Compression Detection** - gzip, Brotli, deflate support
- **Redirect Chain Tracing** - Full redirect path with status codes
- **IPv4/IPv6 Dual-Stack** - Dual-stack availability check
- **Latency Testing** - Response time measurement

### Additional Security Checks
- **CORS Policy Analysis** - Cross-origin resource sharing validation
- **Cookie Security** - Secure, HttpOnly, SameSite attribute analysis
- **robots.txt Analysis** - Crawler directives and sitemap discovery
- **Sitemap.xml Discovery** - XML sitemap detection and parsing
- **SSHFP Records** - SSH fingerprint records for server verification

### DNS Intelligence
- Query A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, CAA, PTR, DNSKEY, DS records
- Batch mode: lookup up to 20 domains in one request
- Resolver profiles: balanced, Google, Cloudflare, Quad9, OpenDNS, or system resolver
- Authoritative vs recursive comparison with mismatch detection
- Subdomain discovery mode with built-in common wordlist
- CNAME chain tracing and final target resolution
- Per-record-type performance timing telemetry
- Domain health insights (SPF, DMARC, MX, CAA)

### Additional Tools
- WHOIS lookup with registration details
- Blacklist/DNSBL checking (Spamhaus, Barracuda, SpamCop)
- Port scanning (common ports)
- GeoIP location lookup
- Global DNS propagation checking across 10+ resolvers
- Filter by record type
- Copy individual records or full batch output
- Export full results as JSON

## Quick Start

```bash
npm install
npm start
# Visit http://localhost:3000
```

## API Endpoints

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ssl` | POST | Full SSL/TLS analysis with grading |
| `/api/security-headers` | POST | Security headers analysis |
| `/api/dnssec` | POST | DNSSEC validation |
| `/api/ocsp` | POST | OCSP/CRL revocation checking |
| `/api/security-score` | POST | Overall security score |
| `/api/mta-sts` | POST | MTA-STS policy analysis |
| `/api/sshfp` | POST | SSHFP records lookup |
| `/api/redirect` | POST | Redirect chain tracing |
| `/api/tech` | POST | Technology fingerprinting |
| `/api/http` | POST | HTTP/2 and compression analysis |
| `/api/mx-smtp` | POST | MX records and SMTP analysis |
| `/api/trace` | POST | IPv4/IPv6 dual-stack test |
| `/api/cors` | POST | CORS policy analysis |
| `/api/cookies` | POST | Cookie security analysis |
| `/api/robots` | POST | robots.txt and sitemap analysis |
| `/api/cert-transparency` | POST | Certificate Transparency lookup |
| `/api/ssl-labs` | POST | SSL Labs API integration |
| `/api/dns-lookup` | POST | DNS record queries |
| `/api/whois` | POST | WHOIS lookup |
| `/api/blacklist` | POST | DNSBL checking |
| `/api/port-scan` | POST | Port scanning |
| `/api/geoip` | POST | GeoIP lookup |
| `/api/propagation` | POST | Global DNS propagation |
| `/api/health` | GET | Health check |

### Example Requests

#### SSL Analysis
```bash
curl -X POST http://localhost:3000/api/ssl \
  -H "Content-Type: application/json" \
  -d '{"domain":"github.com"}'
```

Response includes:
- SSL Labs grade (A+ to F)
- Protocol support (TLS 1.0-1.3)
- Cipher suites with PFS detection
- Certificate chain (leaf, intermediate, root)
- Vulnerability assessments
- Client compatibility simulation
- Recommendations for hardening

#### Security Headers
```bash
curl -X POST http://localhost:3000/api/security-headers \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}'
```

#### Technology Detection
```bash
curl -X POST http://localhost:3000/api/tech \
  -H "Content-Type: application/json" \
  -d '{"domain":"wordpress.com"}'
```

#### DNS Lookup
```bash
curl -X POST http://localhost:3000/api/dns-lookup \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","types":["A","MX","TXT"]}'
```

## Deploy

### Via Coolify
1. Push this repo to your Git provider (GitHub / GitLab / Gitea)
2. In Coolify → **New Resource** → **Application**
3. Connect the repository
4. Coolify will auto-detect the `Dockerfile`
5. Set **Port** to `3000`
6. Set your domain (e.g. `dns.hetops.dev`)
7. Enable **HTTPS** in Coolify settings
8. Click **Deploy**

### Via Azure App Service
1. Create a new Web App on Azure Portal
2. Deploy via GitHub Actions, ZIP, or local Git
3. Set startup command: `npm start`

### Via Docker
```bash
docker build -t hetops-dns .
docker run -p 3000:3000 hetops-dns
```

## Rate Limiting

- General API: 100 requests per 15 minutes per IP
- Heavy endpoints (`/api/ssl`, `/api/propagation`, `/api/trace`): 20 requests per 15 minutes per IP

## Tech Stack

- **Backend**: Node.js, Express.js
- **Frontend**: Vanilla HTML/CSS/JavaScript
- **Rate Limiting**: express-rate-limit
- **WHOIS**: whois library

## License

MIT
