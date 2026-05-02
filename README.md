# OWASP SaaS Hardening Guide

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%20(2021)-brightgreen.svg)](https://owasp.org/Top10/)
[![Stack: Node.js + React](https://img.shields.io/badge/stack-Node.js%20%2B%20React-blue.svg)](#stack-assumed)

> Practical, code-first walkthroughs of the OWASP Top 10 (2021) for a Node.js + Express + React + PostgreSQL SaaS. Every risk is paired with a vulnerable example, the fix, and a test that proves the fix works.

This isn't a theory dump. It's the working notebook I built while hardening the [Forsman CRM](https://github.com/batuhan-satilmis/forsman-crm-showcase) and several client SaaS engagements. Each chapter is scoped to a single OWASP category and contains:

- The **vulnerable pattern** (a small Express handler that has the bug).
- The **fix**, with reasoning.
- A **failing test** that catches the bad version, and a **passing test** for the fixed one.
- Notes on **what NOT to do** that are easy to miss.

Read in order if you're learning. Skip around if you're searching for "how do I fix X."

---

## Audience

- **Engineers** retrofitting security into an existing Node/Express/React app.
- **AppSec hires** evaluating my hands-on depth — every example is something I've done in production.
- **Hiring managers** wanting to verify that "OWASP Top 10" on a resume isn't a buzzword.

## Stack assumed

```
Frontend:  React + TypeScript
Server:    Node.js + Express
Database:  PostgreSQL (with pg or a typed query builder)
Auth:      JWT via HTTP-only session cookies
Tests:     Vitest / Jest
```

The patterns generalize, but examples are concrete.

---

## Chapters

| # | OWASP 2021 | Chapter |
|---|---|---|
| A01 | Broken Access Control | [01-broken-access-control.md](./chapters/01-broken-access-control.md) |
| A02 | Cryptographic Failures | [02-cryptographic-failures.md](./chapters/02-cryptographic-failures.md) |
| A03 | Injection | [03-injection.md](./chapters/03-injection.md) |
| A04 | Insecure Design | [04-insecure-design.md](./chapters/04-insecure-design.md) |
| A05 | Security Misconfiguration | [05-security-misconfiguration.md](./chapters/05-security-misconfiguration.md) |
| A06 | Vulnerable & Outdated Components | [06-vulnerable-components.md](./chapters/06-vulnerable-components.md) |
| A07 | Identification & Authentication Failures | [07-identification-authentication.md](./chapters/07-identification-authentication.md) |
| A08 | Software & Data Integrity Failures | [08-software-data-integrity.md](./chapters/08-software-data-integrity.md) |
| A09 | Security Logging & Monitoring Failures | [09-logging-monitoring.md](./chapters/09-logging-monitoring.md) |
| A10 | Server-Side Request Forgery | [10-ssrf.md](./chapters/10-ssrf.md) |

## Companion code

Every code example referenced here is also runnable from [`/examples`](./examples/). Each chapter has its own folder with `vulnerable.ts`, `secure.ts`, and `*.test.ts`.

```bash
cd examples/01-broken-access-control
npm install
npm test
```

---

## Companion repos

- 🛡️ [**forsman-crm-showcase**](https://github.com/batuhan-satilmis/forsman-crm-showcase) — production application of these controls.
- 🎯 [**threat-modeling-framework**](https://github.com/batuhan-satilmis/threat-modeling-framework) — STRIDE worksheets that pair well with this guide.

---

## Contributing

Found a better fix? An additional gotcha? Open an issue or PR. Discussion welcome.

## License

MIT. See [LICENSE](./LICENSE).
