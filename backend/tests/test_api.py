import pytest
import asyncio
from fastapi.testclient import TestClient
from app.main import app
from app.core.http_client import SecureHTTPClient
from unittest.mock import patch, MagicMock
from app.main import request_history
import httpx

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_scan_endpoint_valid_target():
    """Verify that a valid target returns a successful report."""
    # Clear rate limit history for this test
    request_history.clear()

    with patch('app.main.validate_target') as mock_val, \
         patch('app.core.http_client.SecureHTTPClient.request') as mock_req:

        mock_val.return_value = ("https", "93.184.216.34")

        # A real httpx.Response, shaped like what SecureHTTPClient returns.
        mock_resp = httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            request=httpx.Request("GET", "https://example.com"),
            extensions={"tls_info": {
                "version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "certificate": {
                    "subject": ((("commonName", "example.com"),),),
                    "issuer": ((("organizationName", "Example CA"),),),
                    "notAfter": "Dec 31 23:59:59 2099 GMT",
                },
            }},
        )

        async def mocked_request(*args, **kwargs):
            return mock_resp

        mock_req.side_effect = mocked_request

        response = client.get("/scan?url=https://example.com")
        assert response.status_code == 200
        body = response.json()
        assert body["target_url"] == "https://example.com"
        assert body["validated_ip"] == "93.184.216.34"
        meta = body["scan_metadata"]
        assert meta["tls_version"] == "TLSv1.3"
        assert meta["cert_issuer"] == "Example CA"
        assert meta["cert_subject"] == "example.com"


def test_scan_endpoint_reports_certificate_failure():
    """An invalid certificate produces a report with a finding, not an error."""
    from app.core.http_client import CertificateVerificationError
    request_history.clear()

    async def failing_request(*args, **kwargs):
        raise CertificateVerificationError("certificate has expired")

    with patch('app.main.validate_target', return_value=("https", "93.184.216.34")), \
         patch('app.core.http_client.SecureHTTPClient.request', side_effect=failing_request):
        response = client.get("/scan?url=https://expired.example")

    assert response.status_code == 200
    body = response.json()
    assert [f["id"] for f in body["findings"]] == ["CERT_VERIFICATION_FAILED"]
    assert body["findings"][0]["severity"] == "high"
    assert "certificate has expired" in body["findings"][0]["evidence"]
    assert "skipped" in body["scan_metadata"]["note"]

def test_scan_endpoint_invalid_target():
    """Verify that an invalid target (e.g. localhost) is rejected."""
    response = client.get("/scan?url=http://127.0.0.1")
    assert response.status_code == 400
    assert "Target resolved to a non-public IP" in response.json()["detail"]


def test_rate_limiting():
    """Verify rate limiting is enforced separately for each client IP."""
    from starlette.testclient import TestClient as StarletteTestClient

    request_history.clear()

    # Give each test client a different simulated IP address.
    client_one = StarletteTestClient(
        app,
        client=("1.1.1.1", 12345),
    )
    client_two = StarletteTestClient(
        app,
        client=("2.2.2.2", 12345),
    )

    # Mock the scan so this test tests rate limiting, not DNS/network access.
    async def fake_execute_scan(url):
        return {
            "target_url": url,
            "validated_ip": "93.184.216.34",
            "findings": [],
            "scan_metadata": {"status": "completed"},
        }

    try:
        with patch(
            "app.main._execute_scan",
            side_effect=fake_execute_scan,
        ):
            # The first IP is allowed 10 requests.
            for _ in range(10):
                response = client_one.get("/scan?url=https://example.com")
                assert response.status_code == 200

            # The 11th request from the same IP must be rejected.
            response = client_one.get("/scan?url=https://example.com")
            assert response.status_code == 429

            # A different IP should still be allowed.
            response = client_two.get("/scan?url=https://example.com")
            assert response.status_code == 200
    finally:
        request_history.clear()
        client_one.close()
        client_two.close()
def test_concurrency_limit_fail_fast():
    """Verify that exceeding concurrency limit returns 503 immediately."""
    from app.main import scan_semaphore

    # Force semaphore to be locked
    scan_semaphore._value = 0

    response = client.get("/scan?url=https://example.com")
    assert response.status_code == 503
    assert "full capacity" in response.json()["detail"]

    # Restore semaphore for other tests
    scan_semaphore._value = 3


def test_overlong_url_is_rejected():
    request_history.clear()
    response = client.get("/scan", params={"url": "https://example.com/" + "a" * 3000})
    assert response.status_code == 400
    assert "too long" in response.json()["detail"]


def test_cors_allows_only_get_from_configured_origin():
    allowed = client.options("/scan", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"

    post = client.options("/scan", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"})
    assert post.status_code == 400

    other_origin = client.options("/scan", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in other_origin.headers


def test_rate_limiter_forgets_expired_clients():
    import app.main as main
    request_history.clear()
    # 20 stale clients whose requests are all older than the window
    for i in range(20):
        request_history[f"10.0.0.{i}"] = [0.0]
    async def fake_scan(url):
        return {}

    with patch.object(main, "RATE_LIMIT_SWEEP_THRESHOLD", 5), \
         patch("app.main._execute_scan", side_effect=fake_scan):
        client.get("/scan?url=https://example.com")
    assert all(not ip.startswith("10.0.0.") for ip in request_history)
    request_history.clear()


def test_unexpected_errors_are_logged_but_not_leaked(caplog):
    request_history.clear()

    async def boom(*args, **kwargs):
        raise RuntimeError("internal detail: /etc/secret-path")

    with patch("app.main.validate_target", return_value=("https", "93.184.216.34")), \
         patch("app.core.http_client.SecureHTTPClient.request", side_effect=boom), \
         caplog.at_level("ERROR"):
        response = client.get("/scan?url=https://example.com")

    assert response.status_code == 500
    assert "secret-path" not in response.text
    assert any("Unexpected error" in r.message for r in caplog.records)
    assert any("secret-path" in (r.exc_text or "") or r.exc_info for r in caplog.records)


# --- Client IP behind a hosting proxy (e.g. Vercel's x-real-ip) -------------

def _fake_scan_patch():
    async def fake_scan(url):
        return {}
    return patch("app.main._execute_scan", side_effect=fake_scan)


def test_trusted_ip_header_gives_each_visitor_their_own_limit():
    import app.main as main
    request_history.clear()
    with patch.object(main, "TRUSTED_CLIENT_IP_HEADER", "x-real-ip"), _fake_scan_patch():
        # All requests arrive from the same proxy peer ("testclient")...
        for _ in range(main.RATE_LIMIT_MAX_REQUESTS):
            assert client.get("/scan?url=https://example.com", headers={"x-real-ip": "203.0.113.7"}).status_code == 200
        assert client.get("/scan?url=https://example.com", headers={"x-real-ip": "203.0.113.7"}).status_code == 429
        # ...but a different visitor behind the same proxy is still allowed.
        assert client.get("/scan?url=https://example.com", headers={"x-real-ip": "198.51.100.9"}).status_code == 200
    request_history.clear()


def test_ip_header_is_ignored_unless_configured():
    """Without TRUSTED_CLIENT_IP_HEADER, a caller cannot dodge the limit by faking the header."""
    import app.main as main
    request_history.clear()
    with patch.object(main, "TRUSTED_CLIENT_IP_HEADER", None), _fake_scan_patch():
        for i in range(main.RATE_LIMIT_MAX_REQUESTS):
            client.get("/scan?url=https://example.com", headers={"x-real-ip": f"203.0.113.{i}"})
        response = client.get("/scan?url=https://example.com", headers={"x-real-ip": "198.51.100.200"})
    assert response.status_code == 429
    request_history.clear()


def test_client_ip_for_rejects_malformed_header_values():
    import app.main as main
    from starlette.requests import Request

    def request_with(headers):
        scope = {"type": "http", "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
                 "client": ("10.1.2.3", 1234)}
        return Request(scope)

    with patch.object(main, "TRUSTED_CLIENT_IP_HEADER", "x-real-ip"):
        assert main.client_ip_for(request_with({"x-real-ip": "203.0.113.7"})) == "203.0.113.7"
        assert main.client_ip_for(request_with({"x-real-ip": "203.0.113.7, 10.0.0.1"})) == "203.0.113.7"
        # Garbage or a missing header falls back to the direct peer address.
        assert main.client_ip_for(request_with({"x-real-ip": "not-an-ip"})) == "10.1.2.3"
        assert main.client_ip_for(request_with({})) == "10.1.2.3"


# --- Security headers on the API's own responses ----------------------------

def test_api_responses_carry_security_headers():
    request_history.clear()
    for response in (client.get("/health"), client.get("/scan?url=ftp://x.example")):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "max-age=31536000" in response.headers["strict-transport-security"]
        assert response.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    # The interactive docs still work: no strict CSP there.
    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "content-security-policy" not in docs.headers


def test_sentinel_zero_finds_no_header_issues_in_its_own_api():
    from app.analyzers.header_check import analyze_headers
    assert analyze_headers(client.get("/health")) == []
