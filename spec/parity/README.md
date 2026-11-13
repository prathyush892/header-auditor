# Cross-engine parity cases

The files here are the shared specification for the scan engine. Both engines
load them and must produce identical results:

- Python: `cli-python/tests/test_parity.py`
- TypeScript: `packages/core/test/parity.test.ts`

## `checks.json`

One case per behaviour of a single check. Each case lists raw response headers
as `[name, value]` pairs (order and duplicates matter), optional `isHttps`
(default `true`) and the expected `status`, `score` and `weight`. Both test
suites also assert that every check has at least one case.

## `scoring.json`

- `points`: lists of `{score, weight}` findings and the expected overall
  `score` (0–100) and `grade`. These pin the rounding rule (ties go to the even
  integer, as Python's `round` does) and the grade cutoffs.
- `reports`: raw headers run through every check (`run_all` / `runAll`), with
  the expected `score`, `grade`, `maxScore` and the status of each finding in
  order.

Add a case whenever behaviour changes, so the two engines can't drift apart
silently.
