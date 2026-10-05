# Contributing to HetOps DNS

`main` deploys straight to [dns.hetops.dev](https://dns.hetops.dev), so everything below exists to keep a merge from becoming an outage.

## The hard rules

1. **Never commit a credential.** SMTP passwords, Lemon Squeezy and DMARC ingest secrets, API keys and webhook URLs live in `.env`, which is gitignored. Copy `.env.example` and fill it in locally.
2. **Never put real user data in a test fixture.** DMARC fixtures are synthetic: example domains, and documentation IP ranges or well-known mail-provider IPs, never a report received for someone's real domain.
3. **A check that changes its verdict needs evidence.** Compare against `dig`, another tool, or the RFC on a real domain, and say so in the pull request.

## Running it locally

Node 20 or newer (production runs Node 22; CI also tests 20 and 24).

```bash
git clone https://github.com/Het101/hetops-dns.git
cd hetops-dns
npm install
npm run hooks        # one-off: points git at .githooks
cp .env.example .env # optional; everything has a default
npm run dev          # node --watch, http://localhost:3000
```

With `SMTP_HOST` unset, sign-in links and alert emails are printed to the console instead of being sent, so you can sign in locally without a mail server. Set `APP_URL=http://localhost:3000` so the printed link points at your local server; sign-in links never use the request's own host. `DB_PATH` defaults to `data/hetops.db`.

```bash
npm test             # node --test, no network needed
npm run lint         # syntax check of server.js
```

## Commits

[Conventional Commits](https://www.conventionalcommits.org), subject under 72 characters:

```
fix(dmarc): accept reports with an empty policy_published block
feat(monitoring): alert when an MTA-STS policy expires
```

Types: `feat fix docs test perf refactor build ci chore revert`. No `Co-Authored-By` trailers for tooling.

Commits must be signed — `main` rejects unsigned ones:

```bash
git config commit.gpgsign true
git config rebase.gpgsign true     # without this, a rebase unsigns everything
```

No key yet? SSH signing reuses the key you already push with:

```bash
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
```

then add that public key to <https://github.com/settings/keys> a second time, as a *signing* key. Do not use GitHub's "Update branch" button on a pull request: it rebases on the server and strips signatures. Rebase locally instead.

## Hooks

`npm run hooks` enables three hooks in `.githooks/`:

- `pre-commit` blocks secrets and `.env` files, checks that signing is configured, runs lint and tests when `.js`/`.json` files are staged, and parses workflow YAML if PyYAML is installed.
- `commit-msg` enforces the commit format above.
- `pre-push` refuses unsigned commits.

Skipping them changes nothing in the end: CI runs the same checks before anything can merge.

## Pull requests

One concern per pull request. UI changes should be checked at desktop width and at phone width (~375px). Fill in the template; "what breaks without this" is the part that matters most.
