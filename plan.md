# Plan — header-auditor

1. Design: Python CLI (stdlib only) that fetches a URL and grades its HTTP security headers.
2. Checks: HSTS, CSP, X-Frame-Options / frame-ancestors, X-Content-Type-Options,
   Referrer-Policy, Permissions-Policy, COOP; plus info-leak headers (Server, X-Powered-By)
   and insecure cookie flags.
3. Output: human-readable table or `--json`; score 0–100 with letter grade; exit code for CI.
4. Tests: unit tests for each check + integration tests against a local mock HTTP server
   (127.0.0.1 only, no external targets).
5. Security gate: bandit SAST + secret scan; no credentials in repo.
6. Deploy: README, semantic commit, private repo `prathyush892/header-auditor`, push to `main`.
