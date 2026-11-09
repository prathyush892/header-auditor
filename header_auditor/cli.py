"""Command-line entry point: fetch a URL and print a header report."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

from . import __version__
from .checks import FAIL, PASS, WARN, Headers, Report, run_all

USER_AGENT = f"header-auditor/{__version__} (+security header check)"
COLORS = {PASS: "\033[32m", WARN: "\033[33m", FAIL: "\033[31m"}
RESET = "\033[0m"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


def fetch_headers(url: str, timeout: float = 10.0, follow_redirects: bool = True) -> tuple[str, int, Headers]:
    """Return (final_url, status_code, headers). Only http/https URLs are allowed."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Only absolute http(s) URLs are supported: {url!r}")
    handlers = [] if follow_redirects else [_NoRedirect()]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        resp = opener.open(req, timeout=timeout)  # nosec B310
    except urllib.error.HTTPError as e:  # 4xx/5xx still carry headers worth auditing
        resp = e
    with resp:
        return resp.geturl(), resp.status if hasattr(resp, "status") else resp.code, Headers(resp.headers.items())


def audit(url: str, timeout: float = 10.0, follow_redirects: bool = True) -> Report:
    final_url, code, headers = fetch_headers(url, timeout, follow_redirects)
    is_https = urlparse(final_url).scheme == "https"
    return Report(final_url, code, run_all(headers, is_https))


def render_text(report: Report, color: bool = True) -> str:
    lines = [f"URL:    {report.url}", f"Status: {report.status_code}",
             f"Score:  {report.score}/100  Grade: {report.grade}", ""]
    for f in report.findings:
        tag = f.status.upper().ljust(4)
        if color and f.status in COLORS:
            tag = f"{COLORS[f.status]}{tag}{RESET}"
        lines.append(f"[{tag}] {f.check}: {f.detail}")
        if f.recommendation and f.status != PASS:
            lines.append(f"        -> {f.recommendation}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="header-auditor", description="Audit HTTP security headers of a URL.")
    p.add_argument("url", help="URL to audit (only scan sites you own or are authorized to test)")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--no-redirects", action="store_true", help="audit the first response, don't follow redirects")
    p.add_argument("--min-grade", choices=list("ABCDF"), help="exit 1 if grade is below this (for CI)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)

    try:
        report = audit(args.url, args.timeout, not args.no_redirects)
    except (ValueError, urllib.error.URLError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_text(report, color=not args.no_color and sys.stdout.isatty()))

    if args.min_grade and "ABCDF".index(report.grade) > "ABCDF".index(args.min_grade):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
