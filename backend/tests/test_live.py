"""
Live integration tests: real scans of public websites through the full API.

These need internet access and depend on how third-party sites are configured
today, so they are skipped in the normal run. Run them with:

    python -m pytest -m live -v

If one fails, first check whether the target site changed or is unreachable
from your network before assuming a bug.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app, request_history

pytestmark = pytest.mark.live

client = TestClient(app)


@pytest.fixture(autouse=True)
def _fresh_rate_limit():
    request_history.clear()
    yield
    request_history.clear()


def _scan(url):
    return client.get("/scan", params={"url": url})


def test_live_https_site_returns_a_full_report():
    response = _scan("https://example.com")
    assert response.status_code == 200
    report = response.json()
    assert report["target_url"] == "https://example.com"
    assert report["validated_ip"]
    meta = report["scan_metadata"]
    assert meta["tls_version"].startswith("TLS")
    assert meta["cert_subject"] and meta["cert_issuer"] and meta["cert_valid_until"]
    for finding in report["findings"]:
        assert finding["id"] and finding["severity"] and finding["remediation"]


def test_live_multiple_cookies_are_reported_without_values():
    response = _scan("https://www.google.com")
    assert response.status_code == 200
    cookie_findings = [f for f in response.json()["findings"] if f["id"].startswith("COOKIE_")]
    for finding in cookie_findings:
        assert "(value hidden)" in finding["evidence"]


def test_live_http_redirect_to_https_is_recognised():
    response = _scan("http://github.com")
    assert response.status_code == 200
    ids = [f["id"] for f in response.json()["findings"]]
    assert "HTTP_REDIRECTS_TO_HTTPS" in ids
    assert "NO_HTTPS" not in ids


def test_live_certificate_hostname_mismatch_is_a_finding():
    response = _scan("https://wrong.host.badssl.com")
    assert response.status_code == 200
    findings = response.json()["findings"]
    assert [f["id"] for f in findings] == ["CERT_VERIFICATION_FAILED"]
    assert "Hostname mismatch" in findings[0]["evidence"]


def test_live_unresolvable_host_is_a_clear_error():
    response = _scan("https://nonexistent-host-xyz123.invalid")
    assert response.status_code == 400
    assert "Could not resolve" in response.json()["detail"]


@pytest.mark.parametrize("url", ["http://localhost", "http://169.254.169.254/latest/meta-data/"])
def test_live_internal_targets_are_refused(url):
    response = _scan(url)
    assert response.status_code == 400
    assert "non-public" in response.json()["detail"]
