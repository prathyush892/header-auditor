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


def _csp_directives(csp: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        key, _, value = part.partition(" ")
        out.setdefault(key.lower(), value.strip())
    return out


def check_csp(h: Headers) -> Finding:
    name, weight = "Content-Security-Policy", 25
    val = h.get(name)
    if not val:
        if h.get("Content-Security-Policy-Report-Only"):
            return Finding(name, WARN, "Only a Report-Only policy is set; nothing is enforced.", weight, 5,
                           "Enforce the policy once reports are clean.")
        return Finding(name, FAIL, "Header missing.", weight, 0,
                       "Start with `default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'`.")
    d = _csp_directives(val)
    problems = []
    script_src = d.get("script-src", d.get("default-src", ""))
    if "'unsafe-inline'" in script_src and "'nonce-" not in script_src and "'strict-dynamic'" not in script_src:
        problems.append("script-src allows 'unsafe-inline'")
    if "'unsafe-eval'" in script_src:
        problems.append("script-src allows 'unsafe-eval'")
    if re.search(r"(^|\s)\*(\s|$)", script_src):
        problems.append("script-src allows any origin (*)")
    if "default-src" not in d and "script-src" not in d:
        problems.append("no default-src or script-src")
    if "object-src" not in d and "'none'" not in d.get("default-src", ""):
        problems.append("object-src not restricted")
    if not problems:
        return Finding(name, PASS, "Policy present with no obvious weaknesses.", weight, weight)
    score = max(5, weight - 7 * len(problems))
    return Finding(name, WARN, "; ".join(problems) + ".", weight, score,
                   "Tighten the policy: prefer nonces/hashes over 'unsafe-inline' and set object-src 'none'.")


def check_framing(h: Headers) -> Finding:
    name, weight = "Clickjacking protection", 15
    csp = h.get("Content-Security-Policy") or ""
    fa = _csp_directives(csp).get("frame-ancestors")
    xfo = (h.get("X-Frame-Options") or "").upper()
    if fa is not None:
        if fa.strip() == "*":
            return Finding(name, FAIL, "CSP frame-ancestors allows any origin.", weight, 0,
                           "Use frame-ancestors 'self' or 'none'.")
        return Finding(name, PASS, f"CSP frame-ancestors {fa}.", weight, weight)
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
    last = [p.strip().lower() for p in val.split(",") if p.strip()][-1]
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
