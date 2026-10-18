import ssl
import socket
from datetime import datetime, timezone
from typing import List
import httpx
from app.schemas.report import Finding, Severity

def analyze_ssl(url: str, response: httpx.Response) -> List[Finding]:
    """
    Analyzes the TLS/SSL certificate of the target.
    """
    findings = []

    # Check if HTTPS is used
    if url.startswith("http://"):
        findings.append(Finding(
            id="NO_HTTPS",
            title="Insecure Protocol (HTTP)",
            severity=Severity.HIGH,
            evidence="Scheme: http",
            explanation="The site uses HTTP instead of HTTPS, meaning data is transmitted in plaintext.",
            remediation="Install an SSL/TLS certificate and redirect all HTTP traffic to HTTPS."
        ))
        return findings # Cannot perform certificate checks on plain HTTP

    try:
        # Extract the peer certificate from the response's underlying connection
        # httpx doesn't always expose the raw socket easily in a simple way,
        # but we can use the ssl context from the connection.
        # For a passive analyzer, we check the expiration and validity.

        # Note: httpx verify=True already checks basic validity.
        # We can use the standard ssl library to get detailed info.
        hostname = response.request.url.host
        context = ssl.create_default_context()

        with socket.create_connection((response.request.url.host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Check expiration date
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    # Format: 'Oct 17 12:00:00 2026 GMT'
                    expiry_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    if expiry_date < datetime.now(timezone.utc):
                        findings.append(Finding(
                            id="SSL_EXPIRED",
                            title="Expired SSL Certificate",
                            severity=Severity.CRITICAL,
                            evidence=f"Expired on {not_after_str}",
                            explanation="The SSL certificate has expired, which may lead to browser warnings.",
                            remediation="Renew the SSL certificate immediately."
                        ))
    except Exception as e:
        findings.append(Finding(
            id="SSL_ERROR",
            title="SSL Analysis Failed",
            severity=Severity.LOW,
            evidence=str(e),
            explanation="Could not retrieve certificate details for passive analysis.",
            remediation="Ensure the server is configured with a valid TLS certificate."
        ))

    return findings
