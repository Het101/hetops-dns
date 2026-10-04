## What breaks without this

<!-- The problem, not the diff. If it fixes a bug, what went wrong? -->

## What changed

<!-- Keep it short; the diff has the detail. -->

## Checklist

- [ ] A test fails without this change (or say why one is not possible)
- [ ] `npm test` passes locally
- [ ] No API keys, webhook URLs, SMTP or Lemon Squeezy secrets, or real DMARC report data anywhere in the diff
- [ ] UI changes checked at desktop width and at phone width (~375px)
- [ ] A change to a check's verdict was compared against `dig` or another tool on a real domain
- [ ] One concern in this PR
