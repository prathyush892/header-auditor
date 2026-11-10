"""End-to-end tests against a mock HTTP server bound to 127.0.0.1 only."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from header_auditor.cli import audit, fetch_headers, main

ROUTES = {
    "/secure": [
        ("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "geolocation=()"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Set-Cookie", "sid=abc; HttpOnly; SameSite=Lax"),
    ],
    "/insecure": [
        ("Server", "Apache/2.2.15"),
        ("X-Powered-By", "PHP/5.6"),
        ("Set-Cookie", "sid=abc"),
    ],
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/secure")
            self.end_headers()
            return
        headers = ROUTES.get(self.path)
        self.send_response(200 if headers is not None else 404)
        for k, v in headers or [("X-Content-Type-Options", "nosniff")]:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def base_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_secure_route_scores_high(base_url):
    r = audit(base_url + "/secure")
    assert r.status_code == 200
    assert r.grade == "A"  # HSTS/Secure are N/A over plain HTTP


def test_insecure_route_scores_low(base_url):
    r = audit(base_url + "/insecure")
    assert r.grade == "F"
    leak = next(f for f in r.findings if f.check == "Information disclosure")
    assert "PHP/5.6" in leak.detail


def test_follows_redirects(base_url):
    r = audit(base_url + "/redirect")
    assert r.url.endswith("/secure")
    r2 = audit(base_url + "/redirect", follow_redirects=False)
    assert r2.status_code == 302


def test_http_error_still_audited(base_url):
    _, code, h = fetch_headers(base_url + "/missing")
    assert code == 404 and h.get("x-content-type-options") == "nosniff"


def test_rejects_non_http_schemes():
    with pytest.raises(ValueError):
        fetch_headers("file:///etc/passwd")


def test_cli_json_and_exit_codes(base_url, capsys):
    assert main([base_url + "/secure", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["grade"] == "A"
    assert main([base_url + "/insecure", "--min-grade", "C", "--no-color"]) == 1
    assert main(["ftp://example.invalid"]) == 2
