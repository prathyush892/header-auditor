"""Run the shared cross-engine parity cases (spec/parity/checks.json).

The TypeScript engine runs the same file in packages/core/test/parity.test.ts,
so both implementations are held to one specification.
"""

import json
from pathlib import Path

import pytest

from header_auditor.checks import (
    Headers,
    check_content_type_options,
    check_hsts,
    check_referrer_policy,
)

SPEC = Path(__file__).resolve().parents[2] / "spec" / "parity" / "checks.json"

CHECKS = {
    "hsts": lambda h, is_https: check_hsts(h, is_https),
    "content-type-options": lambda h, _: check_content_type_options(h),
    "referrer-policy": lambda h, _: check_referrer_policy(h),
}


def _cases():
    data = json.loads(SPEC.read_text(encoding="utf-8"))
    assert data["version"] == 1
    return [pytest.param(c, id=f"{c['check']}: {c['name']}") for c in data["cases"]]


@pytest.mark.parametrize("case", _cases())
def test_parity(case):
    run = CHECKS[case["check"]]
    finding = run(Headers(tuple(p) for p in case["headers"]), case.get("isHttps", True))
    expect = case["expect"]
    assert (finding.status, finding.score, finding.weight) == (
        expect["status"], expect["score"], expect["weight"],
    )
