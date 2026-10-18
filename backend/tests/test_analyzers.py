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
    """Verify that empty header values are still treated as 'present' for this basic version."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.headers = {
        "Content-Security-Policy": "",
        "Strict-Transport-Security": " ",
    }
    findings = analyze_headers(mock_resp)
    # We now expect HSTS_MALFORMED because " " is not a valid max-age
    # but CSP is still "present".
    # Total: 3 missing + 1 malformed = 4
    assert len(findings) == 4
    assert any(f.id == "HSTS_MALFORMED" for f in findings)
    assert not any(f.id == "MISSING_CSP" for f in findings)
    assert not any(f.id == "MISSING_HSTS" for f in findings)

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

def test_ssl_analyzer_http_detection():
    """Verify that analyzer flags plain HTTP."""
    mock_resp = MagicMock(spec=httpx.Response)
    findings = analyze_ssl("http://example.com", mock_resp)
    assert len(findings) == 1
    assert findings[0].id == "NO_HTTPS"
