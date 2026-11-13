from header_auditor.checks import (
    FAIL, INFO, PASS, WARN, Headers, Report,
    check_cookies, check_coop, check_csp, check_framing, check_hsts,
    check_info_leak, check_referrer_policy, check_content_type_options, run_all,
)


def H(**kw):
    return Headers((k.replace("_", "-"), v) for k, v in kw.items())


def test_headers_case_insensitive_and_multi():
    h = Headers([("Set-Cookie", "a=1"), ("set-cookie", "b=2"), ("X-TEST", "x")])
    assert h.get("x-test") == "x"
    assert h.get_all("SET-COOKIE") == ["a=1", "b=2"]


def test_hsts():
    assert check_hsts(H()).status == FAIL
    assert check_hsts(H(Strict_Transport_Security="max-age=100")).status == WARN
    assert check_hsts(H(Strict_Transport_Security="max-age=31536000")).status == WARN
    assert check_hsts(H(Strict_Transport_Security="max-age=31536000; includeSubDomains")).status == PASS
    assert check_hsts(H(), is_https=False).status == INFO


def test_csp():
    assert check_csp(H()).status == FAIL
    assert check_csp(H(Content_Security_Policy_Report_Only="default-src 'self'")).status == WARN
    good = "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
    assert check_csp(H(Content_Security_Policy=good)).status == PASS
    weak = check_csp(H(Content_Security_Policy="script-src * 'unsafe-inline' 'unsafe-eval'"))
    assert weak.status == WARN and "unsafe-inline" in weak.detail and "any origin" in weak.detail
    nonce = "default-src 'self'; script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'"
    assert check_csp(H(Content_Security_Policy=nonce)).status == PASS


def test_framing():
    assert check_framing(H()).status == FAIL
    assert check_framing(H(X_Frame_Options="DENY")).status == PASS
    assert check_framing(H(X_Frame_Options="ALLOW-FROM x")).status == WARN
    assert check_framing(H(Content_Security_Policy="frame-ancestors 'self'")).status == PASS
    assert check_framing(H(Content_Security_Policy="frame-ancestors *")).status == FAIL


def test_simple_headers():
    assert check_content_type_options(H(X_Content_Type_Options="nosniff")).status == PASS
    assert check_content_type_options(H()).status == FAIL
    assert check_referrer_policy(H(Referrer_Policy="no-referrer, strict-origin-when-cross-origin")).status == PASS
    assert check_referrer_policy(H(Referrer_Policy="unsafe-url")).status == FAIL
    assert check_referrer_policy(H()).status == WARN
    assert check_coop(H(Cross_Origin_Opener_Policy="same-origin")).status == PASS


def test_info_leak():
    assert check_info_leak(H(Server="nginx")).status == PASS
    leak = check_info_leak(H(Server="Apache/2.4.1", X_Powered_By="PHP/8.1"))
    assert leak.status == WARN and "PHP/8.1" in leak.detail


def test_cookies():
    assert check_cookies(H()).status == INFO
    good = Headers([("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax")])
    assert check_cookies(good).status == PASS
    bad = check_cookies(Headers([("Set-Cookie", "sid=1; Path=/")]))
    assert bad.status == WARN and "Secure/HttpOnly/SameSite" in bad.detail
    # Secure isn't required over plain HTTP
    http = check_cookies(Headers([("Set-Cookie", "sid=1; HttpOnly; SameSite=Lax")]), is_https=False)
    assert http.status == PASS


def test_report_scoring():
    empty = Report("http://x", 200, run_all(H(), is_https=True))
    assert empty.grade == "F"
    strong = H(
        Strict_Transport_Security="max-age=31536000; includeSubDomains",
        Content_Security_Policy="default-src 'self'; object-src 'none'; frame-ancestors 'none'",
        X_Content_Type_Options="nosniff",
        Referrer_Policy="no-referrer",
        Permissions_Policy="camera=()",
        Cross_Origin_Opener_Policy="same-origin",
    )
    r = Report("https://x", 200, run_all(strong, is_https=True))
    assert r.score == 100 and r.grade == "A"
    assert r.to_dict()["grade"] == "A"


def test_parse_csp():
    from header_auditor.checks import parse_csp
    p = parse_csp("\tdefault-src\t'self'\n 'unsafe-inline'; ;FRAME-ANCESTORS; scr!pt-src *; default-src *")
    assert p == {"default-src": ["'self'", "'unsafe-inline'"], "frame-ancestors": []}
    assert parse_csp("Script-SRC 'Nonce-AbC'") == {"script-src": ["'Nonce-AbC'"]}
    assert parse_csp("") == {}


def test_csp_details_match_typescript():
    assert check_csp(H(Content_Security_Policy="default-src 'none'; script-src https:")).detail == \
        "script-src allows any origin (https:)."
    assert check_csp(H(Content_Security_Policy="default-src 'self'")).detail == "object-src not restricted."
    assert check_framing(H(Content_Security_Policy="frame-ancestors")).detail == \
        "CSP frame-ancestors (empty, same as 'none')."
    assert check_framing(H(Content_Security_Policy="frame-ancestors 'self'  https://a.test")).detail == \
        "CSP frame-ancestors 'self' https://a.test."
    assert check_framing(H(Content_Security_Policy="frame-ancestors 'self' *")).detail == \
        "CSP frame-ancestors allows any origin (*)."


def test_coop_ignores_parameters():
    f = check_coop(H(Cross_Origin_Opener_Policy='same-origin; report-to="coop"'))
    assert f.status == PASS and f.detail == "same-origin."
    assert check_coop(H(Cross_Origin_Opener_Policy="unsafe-none; report-to=x")).status == WARN


def test_cookie_attribute_names_are_trimmed():
    f = check_cookies(Headers([("Set-Cookie", "sid=1; Secure ; HttpOnly; SameSite = Lax")]))
    assert f.status == PASS
    bad = check_cookies(Headers([("Set-Cookie", " sid =1; Path=/"), ("Set-Cookie", "tok")]))
    assert bad.detail == "sid missing Secure/HttpOnly/SameSite; tok missing Secure/HttpOnly/SameSite."


def test_report_rounds_half_to_even():
    # 10 of 80 points = 12.5%; Python's round() gives 12, and the TS engine must too.
    r = Report("http://x", 200, run_all(H(), is_https=False))
    assert (r.max_score, r.score) == (80, 12)
