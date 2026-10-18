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

    with patch('app.core.validator.validate_target') as mock_val, \
         patch('app.core.http_client.SecureHTTPClient.request') as mock_req:

        mock_val.return_value = ("https", "1.2.3.4")

        # Use httpx.Headers instead of a dict to support get_list()
        mock_headers = httpx.Headers({"Content-Type": "text/html"})

        # Use AsyncMock for the async request method
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.headers = mock_headers
        mock_resp.request.url.host = "example.com"

        async def mocked_request(*args, **kwargs):
            return mock_resp

        mock_req.side_effect = mocked_request

        response = client.get("/scan?url=https://example.com")
        assert response.status_code == 200
        assert "target_url" in response.json()

def test_scan_endpoint_invalid_target():
    """Verify that an invalid target (e.g. localhost) is rejected."""
    response = client.get("/scan?url=http://127.0.0.1")
    assert response.status_code == 400
    assert "Target resolved to a non-public IP" in response.json()["detail"]

def test_rate_limiting():
    """Verify that exceeding the rate limit returns 429 and is per-IP."""
    request_history.clear()

    # Setup: we need to mock the request.client.host for different "IPs"
    # TestClient usually has a fixed client. We can use a mock or a customized request.
    # Since we are using TestClient, we can't easily change request.client.host
    # without patching the request object in the dependency.

    with patch('fastapi.Request.client') as mock_client:
        # Client 1: hits limit
        mock_client.host = "1.1.1.1"
        for i in range(10):
            client.get("/scan?url=https://example.com")

        response = client.get("/scan?url=https://example.com")
        assert response.status_code == 429

        # Client 2: should still be allowed
        mock_client.host = "2.2.2.2"
        response = client.get("/scan?url=https://example.com")
        assert response.status_code == 200

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
