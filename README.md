# header-auditor

A zero-dependency Python CLI that grades a website's **HTTP security headers** and tells you exactly what to fix.

```
$ header-auditor https://example.com
URL:    https://example.com/
Status: 200
Score:  42/100  Grade: D

[FAIL] Strict-Transport-Security: Header missing.
        -> Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
[WARN] Content-Security-Policy: script-src allows 'unsafe-inline'.
...
```

> **Use responsibly.** Only audit sites you own or are authorized to test. The tool sends a single ordinary GET request; it does not probe or exploit anything.

## What it checks

| Check                      | Weight | Passes when                                                                                   |
| -------------------------- | ------ | --------------------------------------------------------------------------------------------- |
| Strict-Transport-Security  | 20     | `max-age` ≥ 1 year with `includeSubDomains` (HTTPS only)                                      |
| Content-Security-Policy    | 25     | Enforced policy without `unsafe-inline`/`unsafe-eval`/`*` in scripts, `object-src` restricted |
| Clickjacking protection    | 15     | CSP `frame-ancestors` or `X-Frame-Options: DENY/SAMEORIGIN`                                   |
| X-Content-Type-Options     | 10     | `nosniff`                                                                                     |
| Referrer-Policy            | 10     | `no-referrer`, `same-origin`, `strict-origin(-when-cross-origin)`                             |
| Permissions-Policy         | 10     | Present                                                                                       |
| Cross-Origin-Opener-Policy | 5      | `same-origin`                                                                                 |
| Information disclosure     | 5      | No version numbers in `Server` / `X-Powered-By` / ASP.NET headers                             |
| Cookie flags               | 10     | Every `Set-Cookie` has `Secure` (HTTPS), `HttpOnly`, `SameSite`                               |

Score = earned / available × 100. Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, else F. Checks that don't apply (e.g. HSTS over plain HTTP, cookies when none are set) are excluded from the total.

## Install

```bash
git clone https://github.com/prathyush892/header-auditor.git
cd header-auditor/cli-python
pip install .          # or: python -m header_auditor <url> without installing
```

Requires Python 3.9+. No third-party runtime dependencies.

## Usage

```bash
header-auditor https://your-site.example            # coloured table
header-auditor https://your-site.example --json     # machine-readable
header-auditor https://your-site.example --min-grade B   # exit 1 if below B (CI gate)
header-auditor http://localhost:3000 --no-redirects # audit the first response only
```

Exit codes: `0` ok, `1` grade below `--min-grade`, `2` network/usage error.

### As a CI gate

```yaml
- run: pip install "git+https://github.com/prathyush892/header-auditor.git#subdirectory=cli-python"
- run: header-auditor https://staging.your-site.example --min-grade B
```

## Project layout

The repo is a pnpm workspace that is growing into a full scanner platform (see
[ROADMAP.md](ROADMAP.md)). The original Python CLI lives in `cli-python/` and
keeps working on its own.

```
cli-python/
  header_auditor/
    checks.py   # pure functions: headers in, findings out (no network)
    cli.py      # fetching, rendering, argument parsing
  tests/        # unit tests + end-to-end tests against a mock server on 127.0.0.1
packages/
  core/         # TypeScript scan engine (port of the Python checks, in progress)
spec/parity/    # shared test cases both engines must agree on (status, score, weight)
apps/           # API, worker and dashboard (coming in later milestones)
```

## Development

Python CLI:

```bash
cd cli-python
pip install -e ".[dev]"
pytest -q                     # all local, no internet needed
bandit -r header_auditor      # static security analysis
```

TypeScript workspace (Node 22+, pnpm 10):

```bash
corepack enable
pnpm install
pnpm check        # eslint (incl. security rules) + prettier + tsc + vitest
pnpm test:py      # runs the Python suite from the repo root
```

## License

MIT
