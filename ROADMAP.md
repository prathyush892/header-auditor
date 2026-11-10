# Roadmap: header-auditor → full web security scanner

The goal: grow the CLI into a self-hostable security scanning platform with a
Next.js dashboard, a Node API, scheduled scans stored in PostgreSQL, grade-drop
alerts, and TLS/DNS/cookie checks. Each checkbox below is sized for **one day of
work** and lands as one focused commit (or a small group) with tests.

The daily automation picks the **first unchecked item**, implements it, ticks it,
and writes a note in `docs/devlog/` explaining what changed and why.

## Target architecture

```
apps/
  web/        Next.js 15 (App Router) + TypeScript + Tailwind — dashboard
  api/        Node 22 + Fastify + TypeScript — REST API, auth, scan queue
  worker/     Scan runner (BullMQ on Redis) — executes scans, stores results
packages/
  core/       TypeScript scan engine (port of the Python checks) — pure, unit-tested
  db/         Prisma schema + migrations for PostgreSQL
cli-python/   Original Python CLI (kept working and tested)
docker-compose.yml   postgres, redis, api, worker, web — one command to run locally
```

Rules that every step follows:
- Tests only hit local mock servers (127.0.0.1); no real third-party targets.
- No secrets in the repo; config via `.env` (an `.env.example` is committed).
- CI must stay green; `main` only receives passing code.

## Milestone 1: Monorepo + TypeScript engine
- [ ] 1. Restructure into a pnpm workspace: move the Python CLI to `cli-python/` (tests still pass), add root `package.json`, `pnpm-workspace.yaml`, TS config, ESLint + Prettier, update CI for both languages
- [ ] 2. `packages/core`: Headers type + HSTS, X-Content-Type-Options, Referrer-Policy checks ported to TypeScript with Vitest tests mirroring the Python ones
- [ ] 3. `packages/core`: CSP parser + CSP and clickjacking checks, with tests
- [ ] 4. `packages/core`: Permissions-Policy, COOP, info-disclosure, cookie checks + scoring/grade, at parity with the Python engine
- [ ] 5. `packages/core`: `scanUrl()` fetcher (undici) with redirect handling, timeouts, scheme allow-list and SSRF guard (blocks private/loopback IPs unless `allowPrivate`); integration tests against a local mock server

## Milestone 2: New checks
- [ ] 6. TLS check: protocol version, certificate expiry/issuer/hostname match, weak ciphers flag, with a local self-signed test server
- [ ] 7. HTTP→HTTPS redirect check and mixed-content detection in the returned HTML
- [ ] 8. DNS checks: CAA record, SPF and DMARC presence/strength (resolver injected so tests use fixtures)
- [ ] 9. `security.txt` (RFC 9116) and `robots.txt` sensitive-path exposure check
- [ ] 10. Subresource Integrity check for third-party `<script>`/`<link>` tags

## Milestone 3: API + database
- [ ] 11. `packages/db`: Prisma schema (User, Site, Scan, Finding, AlertRule) + first migration; `docker-compose.yml` with Postgres and Redis
- [ ] 12. `apps/api`: Fastify skeleton, health route, zod-validated config, structured logging, error handler, tests with an in-memory app instance
- [ ] 13. Auth: email + password with argon2 hashing, httpOnly session cookies, CSRF protection, rate-limited login, with tests
- [ ] 14. Sites CRUD endpoints (owner-scoped, authorization tests proving users can't read others' sites)
- [ ] 15. Scan queue: `POST /sites/:id/scans` enqueues a BullMQ job; `apps/worker` runs `packages/core` and stores results
- [ ] 16. Scheduled scans (daily/weekly per site) + scan history endpoint with pagination
- [ ] 17. Domain-ownership verification (DNS TXT token) before scheduled scans are allowed

## Milestone 4: Dashboard
- [ ] 18. `apps/web`: Next.js app shell, auth pages, typed API client
- [ ] 19. Sites list + add-site flow with ownership verification instructions
- [ ] 20. Scan report page: grade badge, findings grouped by severity, fix recommendations with copy-paste config snippets (nginx, Express/helmet, Next.js headers)
- [ ] 21. Grade history chart and diff view between two scans ("what got worse")
- [ ] 22. Public shareable report link (opt-in, unguessable ID) + embeddable grade badge SVG

## Milestone 5: Alerts, hardening, ship it
- [ ] 23. Alerts: email/webhook when grade drops or a cert expires within N days
- [ ] 24. Self-audit: run the scanner against its own dashboard in CI and require grade A; add helmet/CSP to the API and web app
- [ ] 25. Security tooling in CI: CodeQL, dependency audit, Dependabot, Docker image scan
- [ ] 26. Playwright end-to-end test: sign up → add site → scan mock target → view report
- [ ] 27. Production Dockerfiles + deploy guide (Fly.io or Railway) and a live demo
- [ ] 28. README overhaul: screenshots/GIF, architecture diagram, threat model section, "design decisions" section
