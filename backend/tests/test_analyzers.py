import pytest
import socket
from unittest.mock import patch, MagicMock, AsyncMock
import httpx
from app.core.http_client import SecureHTTPClient
from app.core.validator import SecurityValidationError
from app.analyzers.header_check import analyze_headers
from app.analyzers.cookie_check import analyze_cookies
from app.analyzers.ssl_check import analyze_ssl
from app.schemas.report import Severity

def test_http_client_validation_before_request():
    """Verify that validation happens before any HTTP request is made."""
    client = SecureHTTPClient()
    url = "http://127.0.0.1"

    with patch('app.core.validator.validate_target') as mock_val, \
         patch('httpx.AsyncClient.stream') as mock_stream:
        # validate_target should raise SecurityValidationError for loopback
        # (No need to mock it as it's actual logic)

        import asyncio
        with pytest.raises(SecurityValidationError):
            asyncio.run(client.request("GET", url))

        # Verify that the actual HTTP request was never attempted
        mock_stream.assert_not_called()

def test_http_client_blocks_redirects():
    """Verify that automatic redirects are disabled."""
    client = SecureHTTPClient()
    url = "https://example.com"

    with patch('app.core.validator.validate_target') as mock_val, \
         patch('httpx.AsyncClient.stream') as mock_stream:

        mock_val.return_value = ("https", "1.2.3.4")
        mock_resp = MagicMock()

        # Correctly mock an async generator for aiter_bytes
        async def mock_aiter():
            yield b"test"

        mock_resp.aiter_bytes = mock_aiter
        mock_resp.headers = {}
        mock_resp.status_code = 302
        mock_resp.request = MagicMock()
        mock_stream.return_value.__aenter__.return_value = mock_resp

        import asyncio
        response = asyncio.run(client.request("GET", url))
        assert response.status_code == 302

def test_http_client_oversized_response():
    """Verify that responses exceeding max_body_size are rejected during streaming."""
    client = SecureHTTPClient(max_body_size=10)
    url = "https://example.com"

    with patch('app.core.validator.validate_target') as mock_val, \
         patch('httpx.AsyncClient.stream') as mock_stream:

        mock_val.return_value = ("https", "1.2.3.4")
        mock_resp = MagicMock()
        async def mock_aiter():
            yield b"this is a very long response"

        mock_resp.aiter_bytes = mock_aiter
        mock_resp.headers = {}
        mock_resp.status_code = 200
        mock_resp.request = MagicMock()
        mock_stream.return_value.__aenter__.return_value = mock_resp

        import asyncio
        with pytest.raises(SecurityValidationError, match="Response body too large"):
            asyncio.run(client.request("GET", url))

# --- HEADER ANALYZER TESTS ---

def test_header_analyzer_missing_headers():
    """Verify that missing security headers are detected."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.headers = {}
    findings = analyze_headers(mock_resp)
    assert len(findings) == 5
    assert any(f.id == "MISSING_HSTS" for f in findings)

def test_header_analyzer_present_headers():
    """Verify that present security headers are NOT reported as missing."""
    mock_resp = MagicMock(spec=httpx.Response)
    # Provide all expected headers
    mock_resp.headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin"
    }
    findings = analyze_headers(mock_resp)
    assert len(findings) == 0

def test_header_analyzer_case_insensitivity():
    """Verify that header name case does not affect detection."""
    mock_resp = MagicMock(spec=httpx.Response)
    # Use httpx.Headers for case-insensitivity as expected in production
    mock_resp.headers = httpx.Headers({
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin"
    })
    findings = analyze_headers(mock_resp)
    assert len(findings) == 0

def test_header_analyzer_empty_values():
    """Empty headers are reported as EMPTY, distinct from MISSING."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.headers = {
        "Content-Security-Policy": "",
        "Strict-Transport-Security": " ",
    }
    findings = analyze_headers(mock_resp)
    ids = {f.id for f in findings}
    # 3 missing + 2 empty = 5
    assert len(findings) == 5
    assert {"CSP_EMPTY", "HSTS_EMPTY"} <= ids
    assert not {"MISSING_CSP", "MISSING_HSTS"} & ids
    csp = next(f for f in findings if f.id == "CSP_EMPTY")
    assert csp.severity == Severity.MEDIUM
    assert "empty" in csp.evidence

def test_header_finding_details():
    """Verify that findings have the correct metadata."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.headers = {}
    findings = analyze_headers(mock_resp)

    hsts = next(f for f in findings if f.id == "MISSING_HSTS")
    assert hsts.title == "Missing Strict-Transport-Security"
    assert hsts.severity == Severity.MEDIUM
    assert hsts.evidence == "Header missing"
    assert "SSL stripping" in hsts.explanation
    assert "long max-age" in hsts.remediation

def test_hsts_validation():
    """Verify deep validation of HSTS max-age."""
    mock_resp = MagicMock(spec=httpx.Response)

    # Case 1: Valid
    mock_resp.headers = {"Strict-Transport-Security": "max-age=31536000"}
    assert not any(f.id in ["HSTS_MALFORMED", "HSTS_WEAK"] for f in analyze_headers(mock_resp))

    # Case 2: Weak (too short)
    mock_resp.headers = {"Strict-Transport-Security": "max-age=3600"}
    findings = analyze_headers(mock_resp)
    assert any(f.id == "HSTS_WEAK" for f in findings)

    # Case 3: Malformed
    mock_resp.headers = {"Strict-Transport-Security": "invalid-value"}
    findings = analyze_headers(mock_resp)
    assert any(f.id == "HSTS_MALFORMED" for f in findings)

    # Case 4: Case insensitivity in value
    mock_resp.headers = {"Strict-Transport-Security": "MAX-AGE=31536000"}
    assert not any(f.id in ["HSTS_MALFORMED", "HSTS_WEAK"] for f in analyze_headers(mock_resp))

def test_csp_validation():
    """Verify deep validation of CSP directives."""
    mock_resp = MagicMock(spec=httpx.Response)

    # Case 1: Secure
    mock_resp.headers = {"Content-Security-Policy": "default-src 'self'; script-src 'self'"}
    assert not any(f.id in ["CSP_WILDCARD", "CSP_UNSAFE_EVAL", "CSP_UNSAFE_INLINE"] for f in analyze_headers(mock_resp))

    # Case 2: Wildcard default-src
    mock_resp.headers = {"Content-Security-Policy": "default-src *; img-src 'self'"}
    findings = analyze_headers(mock_resp)
    assert any(f.id == "CSP_WILDCARD" for f in findings)

    # Case 3: unsafe-eval
    mock_resp.headers = {"Content-Security-Policy": "script-src 'self' 'unsafe-eval'"}
    findings = analyze_headers(mock_resp)
    assert any(f.id == "CSP_UNSAFE_EVAL" for f in findings)

    # Case 4: unsafe-inline
    mock_resp.headers = {"Content-Security-Policy": "style-src 'self' 'unsafe-inline'"}
    findings = analyze_headers(mock_resp)
    assert any(f.id == "CSP_UNSAFE_INLINE" for f in findings)

def test_xfo_validation():
    """Verify deep validation of X-Frame-Options."""
    mock_resp = MagicMock(spec=httpx.Response)

    # Case 1: Valid
    mock_resp.headers = {"X-Frame-Options": "DENY"}
    assert not any(f.id == "XFO_INVALID" for f in analyze_headers(mock_resp))

    # Case 2: Valid
    mock_resp.headers = {"X-Frame-Options": "SAMEORIGIN"}
    assert not any(f.id == "XFO_INVALID" for f in analyze_headers(mock_resp))

    # Case 3: Invalid
    mock_resp.headers = {"X-Frame-Options": "ALLOW-ALL"}
    findings = analyze_headers(mock_resp)
    assert any(f.id == "XFO_INVALID" for f in findings)


def _headers_resp(pairs):
    """Build a mock response from (name, value) pairs; allows repeated headers."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.headers = httpx.Headers(pairs)
    return mock_resp


def _ids(pairs):
    return [f.id for f in analyze_headers(_headers_resp(pairs))]


def test_hsts_edge_cases():
    # max-age=0 disables HSTS rather than merely weakening it
    assert "HSTS_DISABLED" in _ids([("Strict-Transport-Security", "max-age=0")])
    assert "HSTS_WEAK" not in _ids([("Strict-Transport-Security", "max-age=0")])
    # Quoted max-age is valid per RFC 6797
    ids = _ids([("Strict-Transport-Security", 'max-age="31536000"; includeSubDomains')])
    assert not {"HSTS_MALFORMED", "HSTS_WEAK", "HSTS_DISABLED"} & set(ids)
    # Negative / non-numeric values are malformed
    assert "HSTS_MALFORMED" in _ids([("Strict-Transport-Security", "max-age=-5")])
    # Only the first HSTS header is honoured by browsers
    ids = _ids([("Strict-Transport-Security", "max-age=3600"),
                ("Strict-Transport-Security", "max-age=31536000")])
    assert "HSTS_WEAK" in ids


def test_header_evidence_shows_observed_value():
    findings = analyze_headers(_headers_resp([("Strict-Transport-Security", "max-age=3600; preload")]))
    weak = next(f for f in findings if f.id == "HSTS_WEAK")
    assert weak.evidence == "Strict-Transport-Security: max-age=3600; preload"


def test_long_header_evidence_is_truncated():
    long_csp = "default-src 'self'; img-src " + " ".join(f"https://cdn{i}.example.com" for i in range(50))
    findings = analyze_headers(_headers_resp([
        ("Content-Security-Policy", long_csp + "; script-src 'unsafe-eval'"),
        ("X-Frame-Options", "x" * 1000),
    ]))
    xfo = next(f for f in findings if f.id == "XFO_INVALID")
    assert xfo.evidence.endswith("(truncated)")
    assert len(xfo.evidence) < 400


def test_csp_findings_are_deduplicated_with_directive_evidence():
    findings = analyze_headers(_headers_resp([
        ("Content-Security-Policy", "script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'"),
    ]))
    inline = [f for f in findings if f.id == "CSP_UNSAFE_INLINE"]
    assert len(inline) == 1
    assert "script-src 'unsafe-inline'" in inline[0].evidence
    assert "style-src 'unsafe-inline'" in inline[0].evidence


def test_csp_unsafe_inline_ignored_when_nonce_or_hash_present():
    ids = _ids([("Content-Security-Policy", "script-src 'nonce-abc123' 'unsafe-inline'")])
    assert "CSP_UNSAFE_INLINE" not in ids
    ids = _ids([("Content-Security-Policy", "script-src 'sha256-xyz=' 'unsafe-inline'")])
    assert "CSP_UNSAFE_INLINE" not in ids


def test_csp_wildcard_in_script_src_and_no_false_positive_on_img_src():
    assert "CSP_WILDCARD" in _ids([("Content-Security-Policy", "script-src *")])
    assert "CSP_WILDCARD" not in _ids([("Content-Security-Policy", "default-src 'self'; img-src *")])


def test_csp_unsafe_eval_not_matched_by_substring_hostname():
    # A host merely containing the text is not the 'unsafe-eval' keyword
    ids = _ids([("Content-Security-Policy", "script-src https://unsafe-eval.example.com")])
    assert "CSP_UNSAFE_EVAL" not in ids


def test_multiple_csp_headers_are_parsed_separately():
    # httpx would join these with ", " which breaks directive parsing
    ids = _ids([("Content-Security-Policy", "default-src 'self'"),
                ("Content-Security-Policy", "script-src 'unsafe-eval'")])
    assert "CSP_UNSAFE_EVAL" in ids


def test_frame_ancestors_replaces_missing_xfo():
    ids = _ids([("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")])
    assert "MISSING_XFO" not in ids
    # Without frame-ancestors, missing XFO is still reported
    assert "MISSING_XFO" in _ids([("Content-Security-Policy", "default-src 'self'")])


def test_xfo_duplicate_headers():
    assert "XFO_INVALID" not in _ids([("X-Frame-Options", "DENY"), ("X-Frame-Options", "deny")])
    assert "XFO_INVALID" in _ids([("X-Frame-Options", "DENY"), ("X-Frame-Options", "SAMEORIGIN")])
    assert "XFO_INVALID" in _ids([("X-Frame-Options", "ALLOW-FROM https://a.example")])


def test_xcto_validation():
    assert "XCTO_INVALID" not in _ids([("X-Content-Type-Options", "NoSniff")])
    assert "XCTO_INVALID" in _ids([("X-Content-Type-Options", "yes")])


def test_referrer_policy_validation():
    assert "RP_UNSAFE_URL" in _ids([("Referrer-Policy", "unsafe-url")])
    assert "RP_INVALID" in _ids([("Referrer-Policy", "bogus-value")])
    # Comma list: the last recognised token wins (unknown tokens are skipped)
    ids = _ids([("Referrer-Policy", "unsafe-url, strict-origin-when-cross-origin, future-token")])
    assert not {"RP_UNSAFE_URL", "RP_INVALID"} & set(ids)
    assert not {"RP_UNSAFE_URL", "RP_INVALID", "MISSING_RP"} & set(_ids([("Referrer-Policy", "no-referrer")]))


def test_header_finding_ids_are_unique_per_scan():
    findings = analyze_headers(_headers_resp([
        ("Content-Security-Policy", "default-src *; script-src * 'unsafe-eval' 'unsafe-inline'; style-src 'unsafe-inline' 'unsafe-eval'"),
    ]))
    ids = [f.id for f in findings]
    assert len(ids) == len(set(ids))

def test_cookie_analyzer_missing_attributes():
    """Verify that cookies missing Secure/HttpOnly/SameSite are detected."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_headers = MagicMock()
    mock_headers.get_list.return_value = ["session=123; Path=/"]
    mock_resp.headers = mock_headers
    findings = analyze_cookies(mock_resp)
    assert len(findings) == 3
    assert any("HTTPONLY" in f.id for f in findings)
    assert any("SECURE" in f.id for f in findings)
    assert any("SAMESITE" in f.id for f in findings)

def test_cookie_analyzer_secure_cookies():
    """Verify that cookies with all attributes present are not reported."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_headers = MagicMock()
    mock_headers.get_list.return_value = ["session=123; HttpOnly; Secure; SameSite=Lax"]
    mock_resp.headers = mock_headers
    findings = analyze_cookies(mock_resp)
    assert len(findings) == 0

def test_cookie_analyzer_case_insensitivity():
    """Verify that cookie attribute case does not affect detection."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_headers = MagicMock()
    mock_headers.get_list.return_value = ["session=123; httponly; secure; samesite=strict"]
    mock_resp.headers = mock_headers
    findings = analyze_cookies(mock_resp)
    assert len(findings) == 0

def _cookie_findings(*set_cookie_headers):
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.headers = httpx.Headers([("Set-Cookie", h) for h in set_cookie_headers])
    return analyze_cookies(mock_resp)


def test_cookie_evidence_never_contains_value():
    findings = _cookie_findings("session=SUPER_SECRET_TOKEN_123; Path=/")
    assert findings
    for f in findings:
        assert "SUPER_SECRET_TOKEN_123" not in f.evidence
        assert "'session'" in f.evidence
        assert "path=/" in f.evidence


def test_cookies_analyzed_from_raw_headers_even_if_jar_rejects_them():
    """A real httpx.Response drops cookies whose Domain doesn't match; we must not."""
    resp = httpx.Response(
        200,
        headers=[("Set-Cookie", "sid=abc; Domain=other-site.example; Path=/")],
        request=httpx.Request("GET", "https://example.com"),
    )
    assert len(resp.cookies) == 0  # the jar rejected it...
    ids = [f.id for f in analyze_cookies(resp)]
    assert "COOKIE_MISSING_HTTPONLY" in ids  # ...but the analyzer still sees it


def test_multiple_cookies_analyzed_independently():
    findings = _cookie_findings(
        "session=a; Secure; HttpOnly; SameSite=Lax",
        "theme=dark; Path=/",
    )
    assert findings
    assert all("'theme'" in f.evidence for f in findings)


def test_cookie_severity_depends_on_name_sensitivity():
    sens = {f.id: f.severity for f in _cookie_findings("auth_token=x")}
    plain = {f.id: f.severity for f in _cookie_findings("theme=dark")}
    assert sens["COOKIE_MISSING_HTTPONLY"] == Severity.MEDIUM
    assert sens["COOKIE_MISSING_SECURE"] == Severity.MEDIUM
    assert sens["COOKIE_MISSING_SAMESITE"] == Severity.LOW
    assert plain["COOKIE_MISSING_HTTPONLY"] == Severity.LOW
    assert plain["COOKIE_MISSING_SECURE"] == Severity.LOW
    assert plain["COOKIE_MISSING_SAMESITE"] == Severity.INFO


def test_samesite_in_cookie_value_is_not_an_attribute():
    ids = [f.id for f in _cookie_findings("pref=samesite_lax; Secure; HttpOnly")]
    assert "COOKIE_MISSING_SAMESITE" in ids


def test_samesite_none_without_secure_and_invalid_values():
    ids = [f.id for f in _cookie_findings("sid=x; HttpOnly; SameSite=None")]
    assert "COOKIE_SAMESITE_NONE_INSECURE" in ids
    ids = [f.id for f in _cookie_findings("sid=x; HttpOnly; Secure; SameSite=None")]
    assert ids == []
    ids = [f.id for f in _cookie_findings("sid=x; HttpOnly; Secure; SameSite=Bogus")]
    assert ids == ["COOKIE_SAMESITE_INVALID"]


def test_deletion_cookies_are_ignored():
    assert _cookie_findings("session=; Max-Age=0") == []
    assert _cookie_findings("session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT") == []
    assert _cookie_findings("session=; expires=Thu, 01-Jan-1970 00:00:00 GMT; path=/") == []
    # A future expiry is a normal cookie and is still checked
    assert _cookie_findings("session=x; Expires=Fri, 01 Jan 2100 00:00:00 GMT")


def test_cookie_prefix_rules():
    ok = "__Host-sid=x; Secure; HttpOnly; SameSite=Lax; Path=/"
    assert _cookie_findings(ok) == []
    ids = [f.id for f in _cookie_findings("__Host-sid=x; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.com")]
    assert "COOKIE_PREFIX_INVALID" in ids
    ids = [f.id for f in _cookie_findings("__Secure-sid=x; HttpOnly; SameSite=Lax")]
    assert "COOKIE_PREFIX_INVALID" in ids


def test_malformed_and_empty_cookies_do_not_crash():
    assert _cookie_findings("") == []
    findings = _cookie_findings("novalue; HttpOnly")
    assert all("(unnamed)" in f.evidence for f in findings)
    _cookie_findings(";;;", "=x", "a=b; Max-Age=notanumber", "a=b; Expires=garbage")


def _tls_resp(url="https://example.com", status=200, headers=None, tls_info=None):
    """Real httpx.Response shaped like SecureHTTPClient's output."""
    return httpx.Response(
        status,
        headers=headers or {},
        request=httpx.Request("GET", url),
        extensions={"tls_info": tls_info},
    )


def _cert_expiring_in(days):
    import time, ssl as _ssl
    not_after = time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(time.time() + days * 86400 + 3600))
    assert _ssl.cert_time_to_seconds(not_after)  # same format OpenSSL uses
    return {
        "version": "TLSv1.3",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "certificate": {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),)),
            "notAfter": not_after,
        },
    }


def test_ssl_analyzer_http_detection():
    """Verify that analyzer flags plain HTTP."""
    findings = analyze_ssl("http://example.com", _tls_resp("http://example.com"))
    assert len(findings) == 1
    assert findings[0].id == "NO_HTTPS"
    assert findings[0].severity == Severity.HIGH


def test_ssl_analyzer_scheme_is_case_insensitive():
    findings = analyze_ssl("HTTP://example.com", _tls_resp("http://example.com"))
    assert [f.id for f in findings] == ["NO_HTTPS"]


def test_ssl_analyzer_http_redirect_to_https():
    resp = _tls_resp("http://example.com", 301, {"Location": "https://example.com/"})
    findings = analyze_ssl("http://example.com", resp)
    assert [f.id for f in findings] == ["HTTP_REDIRECTS_TO_HTTPS"]
    assert findings[0].severity == Severity.LOW
    # A redirect to another plain-HTTP URL is still NO_HTTPS
    resp = _tls_resp("http://example.com", 301, {"Location": "http://www.example.com/"})
    assert [f.id for f in analyze_ssl("http://example.com", resp)] == ["NO_HTTPS"]


def test_ssl_analyzer_makes_no_network_connections():
    """The analyzer must only use data from the verified client connection."""
    with patch("socket.create_connection") as conn, patch("socket.getaddrinfo") as dns:
        analyze_ssl("https://example.com", _tls_resp(tls_info=_cert_expiring_in(200)))
    conn.assert_not_called()
    dns.assert_not_called()


def test_ssl_analyzer_certificate_expiry_thresholds():
    def ids_and_sev(days):
        return [(f.id, f.severity) for f in analyze_ssl("https://example.com", _tls_resp(tls_info=_cert_expiring_in(days)))]
    assert ids_and_sev(200) == []
    assert ids_and_sev(25) == [("CERT_EXPIRING_SOON", Severity.LOW)]
    assert ids_and_sev(5) == [("CERT_EXPIRING_SOON", Severity.MEDIUM)]


def test_ssl_analyzer_missing_tls_info_is_reported_honestly():
    findings = analyze_ssl("https://example.com", _tls_resp(tls_info=None))
    assert [f.id for f in findings] == ["TLS_DETAILS_UNAVAILABLE"]
    assert findings[0].severity == Severity.INFO


def test_certificate_failure_finding():
    from app.analyzers.ssl_check import certificate_failure_finding
    f = certificate_failure_finding("self-signed certificate")
    assert f.id == "CERT_VERIFICATION_FAILED"
    assert f.severity == Severity.HIGH
    assert f.evidence == "Certificate verification failed: self-signed certificate"


def test_tls_metadata_extracts_observed_details():
    from app.analyzers.ssl_check import tls_metadata
    meta = tls_metadata(_tls_resp(tls_info=_cert_expiring_in(200)))
    assert meta["tls_version"] == "TLSv1.3"
    assert meta["cert_subject"] == "example.com"
    assert meta["cert_issuer"] == "Let's Encrypt"
    assert 199 <= int(meta["cert_days_remaining"]) <= 200
    assert all(isinstance(v, str) for v in meta.values())
    assert tls_metadata(_tls_resp("http://example.com")) == {}


def test_http_client_converts_cert_errors_into_certificate_verification_error():
    """httpx wraps ssl.SSLCertVerificationError; the client must surface its reason."""
    import asyncio, ssl as _ssl
    from app.core.http_client import CertificateVerificationError

    cert_err = _ssl.SSLCertVerificationError(1, "verify failed")
    cert_err.verify_message = "certificate has expired"
    wrapped = httpx.ConnectError("boom")
    wrapped.__cause__ = cert_err

    client = SecureHTTPClient()
    with patch("app.core.http_client.validate_target", return_value=("https", "93.184.216.34")), \
         patch("httpx.AsyncClient.stream", side_effect=wrapped):
        with pytest.raises(CertificateVerificationError) as info:
            asyncio.run(client.request("GET", "https://expired.example"))
    assert info.value.verify_message == "certificate has expired"

    # Ordinary network errors are still generic SecurityValidationErrors
    with patch("app.core.http_client.validate_target", return_value=("https", "93.184.216.34")), \
         patch("httpx.AsyncClient.stream", side_effect=httpx.ConnectError("refused")):
        with pytest.raises(SecurityValidationError) as info:
            asyncio.run(client.request("GET", "https://down.example"))
    assert not isinstance(info.value, CertificateVerificationError)
def test_http_client_preserves_response_headers_and_multiple_cookies():
    """Verify that the HTTP client preserves security headers and Set-Cookie values."""
    import asyncio

    client = SecureHTTPClient()
    url = "https://example.com"

    async def mock_aiter():
        yield b"test body"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = httpx.Headers([
        ("Content-Security-Policy", "default-src 'self'"),
        ("Set-Cookie", "session=abc; HttpOnly; Secure; SameSite=Lax"),
        ("Set-Cookie", "preferences=dark; Secure; SameSite=Strict"),
    ])
    mock_resp.request = httpx.Request("GET", url)
    mock_resp.aiter_bytes = mock_aiter

    async def mock_stream(*args, **kwargs):
        return mock_resp

    with patch(
        "app.core.http_client.validate_target",
        return_value=("https", "93.184.216.34"),
    ), patch("httpx.AsyncClient.stream") as mock_stream_method:
        mock_stream_method.return_value.__aenter__.return_value = mock_resp

        response = asyncio.run(client.request("GET", url))

    assert response.headers["Content-Security-Policy"] == "default-src 'self'"
    cookies = response.headers.get_list("set-cookie")
    assert len(cookies) == 2
    assert "session=abc" in cookies[0]
    assert "preferences=dark" in cookies[1]


def test_http_client_handles_gzip_encoded_response():
    """Regression: a gzip response (e.g. example.com) must not be decoded twice.

    aiter_bytes() yields already-decompressed bytes. Re-attaching the original
    Content-Encoding header made httpx try to gunzip plain HTML, raising
    httpx.DecodingError and surfacing as "An unexpected error occurred during the scan."
    """
    import asyncio

    client = SecureHTTPClient()
    url = "https://example.com"

    async def mock_aiter():
        yield b"<html>already decoded</html>"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = httpx.Headers([
        ("Content-Encoding", "gzip"),
        ("Transfer-Encoding", "chunked"),
        ("Strict-Transport-Security", "max-age=31536000"),
        ("Set-Cookie", "a=1; Secure"),
        ("Set-Cookie", "b=2; HttpOnly"),
    ])
    mock_resp.request = httpx.Request("GET", url)
    mock_resp.aiter_bytes = mock_aiter

    with patch(
        "app.core.http_client.validate_target",
        return_value=("https", "93.184.216.34"),
    ), patch("httpx.AsyncClient.stream") as mock_stream_method:
        mock_stream_method.return_value.__aenter__.return_value = mock_resp

        response = asyncio.run(client.request("GET", url))

    assert response.content == b"<html>already decoded</html>"
    assert "content-encoding" not in response.headers
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000"
    assert len(response.headers.get_list("set-cookie")) == 2
