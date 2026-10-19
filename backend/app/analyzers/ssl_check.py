"""
TLS / HTTPS analyzer.

This analyzer makes no network connections of its own. It only inspects what
SecureHTTPClient observed on the single connection it made and verified:
the URL scheme, redirects, the negotiated TLS version/cipher and the
server certificate.

What a passive check can and cannot tell you:
  - It sees the ONE protocol version and cipher that were negotiated. It cannot
    list every version/cipher the server supports (that needs active probing).
  - Certificates that fail verification (expired, self-signed, wrong host) are
    reported via certificate_failure_finding(); no data is read from such servers.

Severity guide:
  HIGH   - no HTTPS at all; certificate fails verification
  MEDIUM - certificate expires within 14 days
  LOW    - certificate expires within 30 days; HTTP URL that redirects to HTTPS
  INFO   - TLS details could not be read
"""
import ssl
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse
import httpx
from app.schemas.report import Finding, Severity

EXPIRY_WARNING_DAYS = 30
EXPIRY_URGENT_DAYS = 14


def _name_field(name_tuples, key: str) -> Optional[str]:
    """Pull one field (e.g. commonName) out of getpeercert()'s nested tuples."""
    for rdn in name_tuples or ():
        for k, v in rdn:
            if k == key:
                return v
    return None


def _days_remaining(cert: dict) -> Optional[int]:
    not_after = cert.get("notAfter")
    if not not_after:
        return None
    try:
        expires_at = ssl.cert_time_to_seconds(not_after)
    except ValueError:
        return None
    return int((expires_at - time.time()) // 86400)


def analyze_ssl(url: str, response: httpx.Response) -> List[Finding]:
    """
    Analyzes HTTPS usage and the TLS certificate observed by the HTTP client.
    """
    findings = []

    if urlparse(url).scheme.lower() == "http":
        return _analyze_plain_http(response)

    tls_info = response.extensions.get("tls_info")
    if not isinstance(tls_info, dict) or not tls_info.get("certificate"):
        findings.append(Finding(
            id="TLS_DETAILS_UNAVAILABLE",
            title="TLS Details Unavailable",
            severity=Severity.INFO,
            evidence="The connection was verified, but certificate details could not be read.",
            explanation="The HTTPS connection succeeded with certificate verification enabled, "
                        "but this scan could not extract the certificate for further checks.",
            remediation="No action needed; re-run the scan to retry."
        ))
        return findings

    cert = tls_info["certificate"]
    days = _days_remaining(cert)
    if days is not None and days <= EXPIRY_WARNING_DAYS:
        findings.append(Finding(
            id="CERT_EXPIRING_SOON",
            title="TLS Certificate Expires Soon",
            severity=Severity.MEDIUM if days <= EXPIRY_URGENT_DAYS else Severity.LOW,
            evidence=f"Certificate valid until {cert.get('notAfter')} ({days} days remaining)",
            explanation="When the certificate expires, browsers will block visitors with a security warning.",
            remediation="Renew the certificate now, and automate renewal (e.g. ACME / Let's Encrypt) to avoid outages."
        ))

    return findings


def _analyze_plain_http(response: httpx.Response) -> List[Finding]:
    location = response.headers.get("location", "")
    if 300 <= response.status_code < 400 and location.lower().startswith("https://"):
        return [Finding(
            id="HTTP_REDIRECTS_TO_HTTPS",
            title="HTTP Redirects to HTTPS",
            severity=Severity.LOW,
            evidence=f"HTTP {response.status_code} redirect to {location[:200]}",
            explanation="The plain-HTTP address redirects to HTTPS, which is good. The first request is still "
                        "sent unencrypted, so an attacker on the network could intercept it before the redirect. "
                        "Header and cookie results in this report describe the redirect response, not the real page.",
            remediation="Enable HSTS on the HTTPS site (and consider HSTS preload). Scan the HTTPS URL for full results."
        )]
    return [Finding(
        id="NO_HTTPS",
        title="Insecure Protocol (HTTP)",
        severity=Severity.HIGH,
        evidence=f"Scheme: http (HTTP {response.status_code}, no redirect to HTTPS)",
        explanation="The site uses HTTP instead of HTTPS, meaning data is transmitted in plaintext.",
        remediation="Install an SSL/TLS certificate and redirect all HTTP traffic to HTTPS."
    )]


def certificate_failure_finding(verify_message: str) -> Finding:
    """Finding for a certificate that failed verification (raised by SecureHTTPClient)."""
    return Finding(
        id="CERT_VERIFICATION_FAILED",
        title="TLS Certificate Verification Failed",
        severity=Severity.HIGH,
        evidence=f"Certificate verification failed: {verify_message[:200]}",
        explanation="Browsers will show a full-page security warning. Visitors who click through cannot tell "
                    "whether they are talking to the real site or an attacker intercepting the connection.",
        remediation="Install a valid certificate from a trusted authority that matches this hostname, "
                    "and include the full intermediate chain."
    )


def tls_metadata(response: httpx.Response) -> Dict[str, str]:
    """Observed TLS details for the report's scan_metadata (strings only)."""
    tls_info = response.extensions.get("tls_info")
    if not isinstance(tls_info, dict):
        return {}
    cert = tls_info.get("certificate") or {}
    days = _days_remaining(cert)
    values = {
        "tls_version": tls_info.get("version"),
        "tls_cipher": tls_info.get("cipher"),
        "cert_subject": _name_field(cert.get("subject"), "commonName"),
        "cert_issuer": _name_field(cert.get("issuer"), "organizationName")
                       or _name_field(cert.get("issuer"), "commonName"),
        "cert_valid_until": cert.get("notAfter"),
        "cert_days_remaining": str(days) if days is not None else None,
    }
    return {k: v for k, v in values.items() if v}
