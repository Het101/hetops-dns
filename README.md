# DNS Lookup — HetOps.dev Tool

A DNS record lookup tool that queries all major DNS record types for any domain. Built for HetOps.dev, deployable via Coolify.

## Features

- Query A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, CAA, PTR records
- Batch mode: lookup up to 20 domains in one request
- Resolver profiles: balanced, Google, Cloudflare, Quad9, OpenDNS, or system resolver
- Optional authoritative vs recursive comparison with mismatch detection
- Subdomain discovery mode with a built-in common wordlist
- CNAME chain tracing and final target resolution
- Per-record-type performance timing telemetry
- Domain health insights (SPF, DMARC, MX, CAA)
- Filter by record type
- Copy individual records or full batch output
- Export full results as JSON and share query links

## Deploy via Coolify

1. Push this repo to your Git provider (GitHub / GitLab / Gitea)
2. In Coolify → **New Resource** → **Application**
3. Connect the repository
4. Coolify will auto-detect the `Dockerfile`
5. Set **Port** to `3000`
6. Set your domain (e.g. `dns.hetops.dev`)
7. Enable **HTTPS** in Coolify settings
8. Click **Deploy**

## Run Locally

```bash
npm install
npm start
# Visit http://localhost:3000
```

## API

### POST /api/dns-lookup

```json
{
  "domains": ["example.com", "hetops.dev"],
  "types": ["A", "MX", "TXT"],
  "resolver": "balanced",
  "compareAuthoritative": true,
  "discoverSubdomains": true
}
```

Also supported for backward compatibility:

```json
{
  "domain": "example.com"
}
```

Response:
```json
{
  "timestamp": "2024-01-01T00:00:00.000Z",
  "durationMs": 192,
  "resolver": {
    "profile": "balanced",
    "servers": ["8.8.8.8", "1.1.1.1"]
  },
  "query": {
    "domains": ["example.com"],
    "types": ["A", "MX", "TXT"]
  },
  "lookups": [
    {
      "domain": "example.com",
      "results": {
        "A": [{ "value": "93.184.216.34", "ttl": 300 }],
        "MX": [{ "value": "mail.example.com", "priority": 10 }]
      },
      "metrics": {
        "A": { "durationMs": 14, "count": 1 },
        "MX": { "durationMs": 9, "count": 1 }
      },
      "insights": {
        "status": "strong",
        "score": 3,
        "checks": { "spf": true, "dmarc": true, "mx": true, "caa": false }
      },
      "authoritative": {
        "enabled": true,
        "available": true,
        "mismatchedTypes": ["TXT"]
      }
    }
  ],
  "summary": {
    "domains": 1,
    "totalRecords": 2,
    "totalErrors": 0,
    "discoveredHosts": 4,
    "discoveredScanned": 30
  }
}
```

Discovery output is included per domain in:

```json
{
  "discovery": {
    "enabled": true,
    "scanned": 30,
    "found": 4,
    "hosts": [
      {
        "host": "www.example.com",
        "records": {
          "A": [{ "value": "93.184.216.34" }],
          "AAAA": [],
          "CNAME": [{ "value": "example.com" }]
        },
        "cnameChain": {
          "chain": [{ "from": "www.example.com", "to": "example.com" }],
          "finalHost": "example.com",
          "depth": 1
        },
        "finalTarget": {
          "host": "example.com",
          "A": [{ "value": "93.184.216.34" }],
          "AAAA": []
        }
      }
    ]
  }
}
```

### GET /api/health

Returns service health status.
