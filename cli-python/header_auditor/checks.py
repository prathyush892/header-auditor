"""Pure functions that grade a set of HTTP response headers.

Every check takes a case-insensitive header mapping and returns a Finding.
No network access happens here, which keeps the logic easy to unit test.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable, Mapping

PASS, WARN, FAIL, INFO = "pass", "warn", "fail", "info"


@dataclass
class Finding:
    check: str
    status: str
    detail: str
    weight: int = 0  # points available for this check
    score: int = 0  # points earned
    recommendation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    url: str
    status_code: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def max_score(self) -> int:
        return sum(f.weight for f in self.findings)

    @property
    def score(self) -> int:
        if not self.max_score:
            return 0
        return round(100 * sum(f.score for f in self.findings) / self.max_score)

    @property
    def grade(self) -> str:
        s = self.score
        for cutoff, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
            if s >= cutoff:
                return letter
        return "F"

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "score": self.score,
            "grade": self.grade,
            "findings": [f.to_dict() for f in self.findings],
        }


class Headers:
    """Case-insensitive, multi-value header view."""

    def __init__(self, items: Iterable[tuple[str, str]]):
        self._items: dict[str, list[str]] = {}
        for k, v in items:
            self._items.setdefault(k.lower(), []).append(v.strip())

    @classmethod
    def from_mapping(cls, m: Mapping[str, str]) -> "Headers":
        return cls(m.items())

    def get(self, name: str) -> str | None:
        vals = self._items.get(name.lower())
        return vals[0] if vals else None

    def get_all(self, name: str) -> list[str]:
        return list(self._items.get(name.lower(), []))


# --- individual checks -------------------------------------------------------

ONE_YEAR = 31536000
HALF_YEAR = 15768000


def check_hsts(h: Headers, is_https: bool = True) -> Finding:
    name, weight = "Strict-Transport-Security", 20
    if not is_https:
        return Finding(name, INFO, "Not applicable over plain HTTP; serve the site over HTTPS.", 0, 0)
    val = h.get(name)
    if not val:
        return Finding(name, FAIL, "Header missing.", weight, 0,
                       f"Add `{name}: max-age={ONE_YEAR}; includeSubDomains`.")
    m = re.search(r"max-age\s*=\s*\"?(\d+)", val, re.I)
    if not m:
        return Finding(name, FAIL, f"No valid max-age in '{val}'.", weight, 0, "Set max-age to at least one year.")
    age = int(m.group(1))
    if age < HALF_YEAR:
        return Finding(name, WARN, f"max-age={age} is shorter than 6 months.", weight, weight // 2,
                       f"Raise max-age to {ONE_YEAR}.")
    detail = f"max-age={age}"
    if "includesubdomains" not in val.lower():
        return Finding(name, WARN, detail + " without includeSubDomains.", weight, weight - 5,
                       "Add includeSubDomains if all subdomains serve HTTPS.")
    return Finding(name, PASS, detail + " with includeSubDomains.", weight, weight)


# --- Content-Security-Policy parsing ------------------------------------------
# Mirrors packages/core/src/csp.ts (CSP Level 3, "parse a serialized CSP"):
# split on ";", strip ASCII whitespace, lowercase the directive name, ignore
# invalid names and duplicates (first wins), split the value into source tokens.

_ASCII_WS = re.compile(r"[\t\n\f\r ]+")
_DIRECTIVE_NAME = re.compile(r"[a-z0-9-]+")
_ANY_ORIGIN_SOURCE = re.compile(r"\*|https?:|https?://\*")
_HASH_PREFIXES = ("'sha256-", "'sha384-", "'sha512-")


def parse_csp(serialized: str) -> dict[str, list[str]]:
    """Parse one serialized policy into {directive: [source tokens]}."""
    policy: dict[str, list[str]] = {}
    for raw in serialized.split(";"):
        tokens = [t for t in _ASCII_WS.split(raw) if t]
        if not tokens:
            continue
        name = tokens[0].lower()
        if not _DIRECTIVE_NAME.fullmatch(name) or name in policy:
            continue
        policy[name] = tokens[1:]
    return policy


def _has_source(sources: list[str], keyword: str) -> bool:
    return any(s.lower() == keyword.lower() for s in sources)


def _has_source_prefix(sources: list[str], prefix: str) -> bool:
    return any(s.lower().startswith(prefix.lower()) for s in sources)


def _any_origin_source(sources: list[str]) -> str | None:
    return next((s for s in sources if _ANY_ORIGIN_SOURCE.fullmatch(s.lower())), None)


def _neutralizes_unsafe_inline(sources: list[str]) -> bool:
    """Browsers ignore 'unsafe-inline' next to a nonce, hash or 'strict-dynamic'."""
    return (_has_source_prefix(sources, "'nonce-")
            or any(_has_source_prefix(sources, p) for p in _HASH_PREFIXES)
            or _has_source(sources, "'strict-dynamic'"))


def csp_problems(policy: dict[str, list[str]]) -> list[str]:
    problems = []
    script_src = policy.get("script-src", policy.get("default-src", []))
    if _has_source(script_src, "'unsafe-inline'") and not _neutralizes_unsafe_inline(script_src):
        problems.append("script-src allows 'unsafe-inline'")
    if _has_source(script_src, "'unsafe-eval'"):
        problems.append("script-src allows 'unsafe-eval'")
    # With 'strict-dynamic', CSP3 browsers ignore host and scheme sources.
    any_origin = None if _has_source(script_src, "'strict-dynamic'") else _any_origin_source(script_src)
    if any_origin is not None:
        problems.append(f"script-src allows any origin ({any_origin})")
    if "default-src" not in policy and "script-src" not in policy:
        problems.append("no default-src or script-src")
    if "object-src" not in policy and not _has_source(policy.get("default-src", []), "'none'"):
        problems.append("object-src not restricted")
    return problems


def check_csp(h: Headers) -> Finding:
    name, weight = "Content-Security-Policy", 25
    val = h.get(name)
    if not val:
        if h.get("Content-Security-Policy-Report-Only"):
            return Finding(name, WARN, "Only a Report-Only policy is set; nothing is enforced.", weight, 5,
                           "Enforce the policy once reports are clean.")
        return Finding(name, FAIL, "Header missing.", weight, 0,
                       "Start with `default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'`.")
    problems = csp_problems(parse_csp(val))
    if not problems:
        return Finding(name, PASS, "Policy present with no obvious weaknesses.", weight, weight)
    score = max(5, weight - 7 * len(problems))
    return Finding(name, WARN, "; ".join(problems) + ".", weight, score,
                   "Tighten the policy: prefer nonces/hashes over 'unsafe-inline' and set object-src 'none'.")


def check_framing(h: Headers) -> Finding:
    name, weight = "Clickjacking protection", 15
    csp = h.get("Content-Security-Policy")
    fa = parse_csp(csp).get("frame-ancestors") if csp is not None else None
    xfo = (h.get("X-Frame-Options") or "").upper()
    if fa is not None:
        any_origin = _any_origin_source(fa)
        if any_origin is not None:
            return Finding(name, FAIL, f"CSP frame-ancestors allows any origin ({any_origin}).", weight, 0,
                           "Use frame-ancestors 'self' or 'none'.")
        shown = " ".join(fa) if fa else "(empty, same as 'none')"
        return Finding(name, PASS, f"CSP frame-ancestors {shown}.", weight, weight)
    if xfo in ("DENY", "SAMEORIGIN"):
        return Finding(name, PASS, f"X-Frame-Options: {xfo}.", weight, weight)
    if xfo:
        return Finding(name, WARN, f"Unsupported X-Frame-Options value '{xfo}'.", weight, 5,
                       "Use DENY or SAMEORIGIN, or CSP frame-ancestors.")
    return Finding(name, FAIL, "No X-Frame-Options or CSP frame-ancestors.", weight, 0,
                   "Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.")


def check_content_type_options(h: Headers) -> Finding:
    name, weight = "X-Content-Type-Options", 10
    val = (h.get(name) or "").lower()
    if val == "nosniff":
        return Finding(name, PASS, "nosniff.", weight, weight)
    if val:
        return Finding(name, WARN, f"Unexpected value '{val}'.", weight, 3, "Set to `nosniff`.")
    return Finding(name, FAIL, "Header missing.", weight, 0, f"Add `{name}: nosniff`.")


SAFE_REFERRER = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}


def check_referrer_policy(h: Headers) -> Finding:
    name, weight = "Referrer-Policy", 10
    val = h.get(name)
    if not val:
        return Finding(name, WARN, "Header missing (browser default applies).", weight, 5,
                       f"Add `{name}: strict-origin-when-cross-origin`.")
    tokens = [p.strip().lower() for p in val.split(",") if p.strip()]
    if not tokens:
        return Finding(name, WARN, f"No policy token in '{val}' (browser default applies).", weight, 5,
                       "Use strict-origin-when-cross-origin.")
    last = tokens[-1]
    if last in SAFE_REFERRER:
        return Finding(name, PASS, f"{last}.", weight, weight)
    if last == "unsafe-url":
        return Finding(name, FAIL, "unsafe-url leaks full URLs to every site.", weight, 0,
                       "Use strict-origin-when-cross-origin.")
    return Finding(name, WARN, f"'{last}' can leak path data.", weight, 5, "Use strict-origin-when-cross-origin.")


def check_permissions_policy(h: Headers) -> Finding:
    name, weight = "Permissions-Policy", 10
    if h.get(name):
        return Finding(name, PASS, "Present.", weight, weight)
    return Finding(name, WARN, "Header missing.", weight, 0,
                   f"Add e.g. `{name}: camera=(), microphone=(), geolocation=()`.")


def check_coop(h: Headers) -> Finding:
    name, weight = "Cross-Origin-Opener-Policy", 5
    val = (h.get(name) or "").lower()
    if val in ("same-origin", "same-origin-allow-popups"):
        return Finding(name, PASS, f"{val}.", weight, weight)
    return Finding(name, WARN, "Missing or permissive.", weight, 0, f"Add `{name}: same-origin`.")


LEAKY = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")


def check_info_leak(h: Headers) -> Finding:
    name, weight = "Information disclosure", 5
    leaks = []
    for hdr in LEAKY:
        v = h.get(hdr)
        if v and (hdr != "Server" or re.search(r"\d", v)):
            leaks.append(f"{hdr}: {v}")
    if leaks:
        return Finding(name, WARN, "Exposes " + ", ".join(leaks) + ".", weight, 0,
                       "Remove version details from these headers.")
    return Finding(name, PASS, "No version-revealing headers.", weight, weight)


def check_cookies(h: Headers, is_https: bool = True) -> Finding:
    name = "Cookie flags"
    cookies = h.get_all("Set-Cookie")
    if not cookies:
        return Finding(name, INFO, "No cookies set.", 0, 0)
    weight = 10
    issues = []
    for c in cookies:
        cname = c.split("=", 1)[0].strip()
        attrs = [a.strip().lower() for a in c.split(";")[1:]]
        flags = {a.split("=", 1)[0] for a in attrs}
        missing = []
        if is_https and "secure" not in flags:
            missing.append("Secure")
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "samesite" not in flags:
            missing.append("SameSite")
        if missing:
            issues.append(f"{cname} missing {'/'.join(missing)}")
    if not issues:
        return Finding(name, PASS, f"All {len(cookies)} cookie(s) have Secure/HttpOnly/SameSite.", weight, weight)
    return Finding(name, WARN, "; ".join(issues) + ".", weight, max(0, weight - 3 * len(issues)),
                   "Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies.")


def run_all(h: Headers, is_https: bool) -> list[Finding]:
    checks: list[Callable[[], Finding]] = [
        lambda: check_hsts(h, is_https),
        lambda: check_csp(h),
        lambda: check_framing(h),
        lambda: check_content_type_options(h),
        lambda: check_referrer_policy(h),
        lambda: check_permissions_policy(h),
        lambda: check_coop(h),
        lambda: check_info_leak(h),
        lambda: check_cookies(h, is_https),
    ]
    return [c() for c in checks]
