"""Run the shared cross-engine parity cases (spec/parity/checks.json).

The TypeScript engine runs the same file in packages/core/test/parity.test.ts,
so both implementations are held to one specification.
"""

import json
from pathlib import Path

import pytest

from header_auditor.checks import (
    Finding,
    Headers,
    Report,
    check_content_type_options,
    check_cookies,
    check_coop,
    check_csp,
    check_framing,
    check_hsts,
    check_info_leak,
    check_permissions_policy,
    check_referrer_policy,
    run_all,
)

SPEC_DIR = Path(__file__).resolve().parents[2] / "spec" / "parity"
SPEC = SPEC_DIR / "checks.json"
SCORING = SPEC_DIR / "scoring.json"

CHECKS = {
    "hsts": lambda h, is_https: check_hsts(h, is_https),
    "content-type-options": lambda h, _: check_content_type_options(h),
    "referrer-policy": lambda h, _: check_referrer_policy(h),
    "csp": lambda h, _: check_csp(h),
    "framing": lambda h, _: check_framing(h),
    "permissions-policy": lambda h, _: check_permissions_policy(h),
    "coop": lambda h, _: check_coop(h),
    "info-disclosure": lambda h, _: check_info_leak(h),
    "cookies": lambda h, is_https: check_cookies(h, is_https),
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


def test_every_check_has_parity_cases():
    data = json.loads(SPEC.read_text(encoding="utf-8"))
    assert {c["check"] for c in data["cases"]} == set(CHECKS)


def _scoring():
    data = json.loads(SCORING.read_text(encoding="utf-8"))
    assert data["version"] == 1
    return data


@pytest.mark.parametrize("case", [pytest.param(c, id=c["name"]) for c in _scoring()["points"]])
def test_scoring_points(case):
    findings = [Finding("c", "pass", "", f["weight"], f["score"]) for f in case["findings"]]
    report = Report("https://x", 200, findings)
    assert (report.score, report.grade) == (case["expect"]["score"], case["expect"]["grade"])


@pytest.mark.parametrize("case", [pytest.param(c, id=c["name"]) for c in _scoring()["reports"]])
def test_scoring_reports(case):
    headers = Headers(tuple(p) for p in case["headers"])
    report = Report("https://x", 200, run_all(headers, case["isHttps"]))
    expect = case["expect"]
    assert report.score == expect["score"]
    assert report.grade == expect["grade"]
    assert report.max_score == expect["maxScore"]
    assert [f.status for f in report.findings] == expect["statuses"]
