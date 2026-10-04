# Security policy

HetOps DNS is a hosted service at [dns.hetops.dev](https://dns.hetops.dev). Scanning a domain needs no account, and scan results are public DNS and TLS data. Signing in adds things that are not public, and that is what this policy is mostly about.

## What it holds

| Data | Where it comes from | How it is stored |
|---|---|---|
| Account email address | You, at sign-in | Plain text in the SQLite database |
| Sign-in links | Emailed on request | Random 24-byte token, single use, expires after 15 minutes; requesting a new one invalidates the old ones. Stored as-is, not hashed |
| Sessions | Created when a sign-in link is used | Random 32-byte id in an `HttpOnly`, `SameSite=Lax` cookie, `Secure` in production, 30 days. Stored as-is, not hashed |
| API keys (`hk_...`) | Created by you in the dashboard | **Stored as-is, not hashed.** Anyone who can read the database can use them. Delete a key you no longer need |
| Watched domains, scan history, alert events | Your monitoring settings | Plain text; history and events are trimmed to a fixed length per user |
| Alert webhook URL | You, in settings | Plain text. Treat it as a credential on your side too |
| DMARC aggregate reports | Mail providers, via your private `dmarc-<token>@hetops.dev` address | Parsed XML stored per user. Reports contain the sending IP addresses seen for your domain. There is no self-serve deletion yet; email to have them removed |
| Billing | [Lemon Squeezy](https://www.lemonsqueezy.com) hosted checkout | Card details never reach this app. It stores which plan your account is on, as reported by signed Lemon Squeezy webhooks |

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use [GitHub's private vulnerability reporting](https://github.com/Het101/hetops-dns/security/advisories/new) on this repository. If that is unavailable to you, email patel.x.het@gmail.com with "security" in the subject and no detail, and a private channel will be arranged.

Please include:

- What the problem is and what an attacker gets out of it.
- The smallest reproduction you can manage.
- Roughly when you saw it, since the site deploys continuously.

**Test against your own account and your own domains.** Never include another person's data, a real API key, a webhook URL or a sign-in link in a report.

Expect an acknowledgement within 3 working days and an assessment within 10. You will be credited in the fix's pull request unless you would rather not be.

## Supported versions

Only what is live on dns.hetops.dev. It deploys from `main`, so a fix is supported the moment it merges. There are no releases or maintained branches. If you self-host from this repository, track `main`.

## What the code does to protect it

Each line here is something the code actually does. A defect in any of them is a security bug:

| Protection | Where |
|---|---|
| Lemon Squeezy webhooks are only trusted with a valid HMAC-SHA256 signature, compared in constant time | `billing.js` `verifySignature`, `/api/billing/webhook` in `server.js` |
| DMARC ingestion requires a shared secret of at least 16 characters, compared in constant time, and is off when the secret is unset. Unknown addresses get the same response as known ones, so the endpoint does not reveal which addresses exist | `/api/dmarc/ingest` in `server.js` |
| Scans of a user-supplied domain refuse to target loopback, private, link-local, CGNAT, multicast and metadata ranges (IPv4, IPv6 and IPv4-mapped IPv6) | `ssrfGuard` / `isBlockedIp` in `server.js` |
| Rate limits per IP, and per key for API callers, with a tighter limit on expensive checks and on sign-in requests | `express-rate-limit` setup in `server.js` |
| A Content-Security-Policy on every page | `server.js` |
| Secrets do not enter the git history | `.githooks/pre-commit` and the `hygiene` CI job block private keys, AWS keys, Slack webhooks, SMTP/database URLs with passwords, npm tokens and `.env` files |

Known limits, so nobody mistakes them for guarantees:

- The SSRF check resolves the hostname and checks the answers before the scan runs. It is not pinned to the connection the scan then makes, so a domain that changes its DNS answer between the two (DNS rebinding) is not fully covered.
- API keys, session ids and sign-in tokens are not hashed at rest (see above).

## Things that are not vulnerabilities

- **Scan results for any domain are visible to anyone who scans it.** They are public DNS and TLS data.
- **The site reports a misconfiguration on a domain you do not own.** That is the product. A *wrong* result is a bug — use the "Wrong or misleading result" issue form.

## How the supply chain is checked

| Tool | Runs | Catches |
|---|---|---|
| [CodeQL](https://github.com/Het101/hetops-dns/security/code-scanning) | push, PR, weekly | Injection, SSRF, XSS and the rest of the security-and-quality JavaScript pack |
| [zizmor](https://docs.zizmor.sh) | every PR and push to `main` | Vulnerabilities in the workflows themselves: template injection, tokens left in `.git/config`, cache poisoning, unpinned actions |
| [Dependency Review](.github/workflows/dependency-review.yml) | every PR | A dependency added in that PR carrying a known high advisory, or a copyleft licence |
| `npm audit --audit-level=high` | every PR and push to `main` | Known high or critical advisories anywhere in the dependency tree, dev dependencies included |
| [OpenSSF Scorecard](https://github.com/Het101/hetops-dns/security/code-scanning) | push to `main`, weekly | Posture drift — branch protection weakened, a permission widened, an action unpinned |
| [Dependabot](.github/dependabot.yml) | weekly (npm), monthly (actions, Docker base image) | Outdated dependencies, proposed only after a 7-day cooldown (14 for majors), since most malicious releases are pulled within a day or two |
| [Harden-Runner](https://github.com/step-security/harden-runner) | every CI job that installs or runs dependencies | Outbound network calls made *while* the build runs. Audit mode for now: it records, it does not block |

- **Every action is pinned to a commit SHA**, not a tag. A tag can be moved; a SHA cannot.
- **Workflows default to `contents: read`.** Jobs that need more ask for it themselves.

There are no accepted advisories today: `npm audit` reports zero.
