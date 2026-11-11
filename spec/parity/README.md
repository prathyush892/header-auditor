# Cross-engine parity cases

`checks.json` is the shared specification for the security checks. Both
engines load the same file and must produce the same `status`, `score` and
`weight` for every case:

- Python: `cli-python/tests/test_parity.py`
- TypeScript: `packages/core/test/parity.test.ts`

Each case lists raw response headers as `[name, value]` pairs (order and
duplicates matter), optional `isHttps` (default `true`) and the expected result.
Add a case here whenever a check's behaviour changes, so the two engines can't
drift apart silently.
