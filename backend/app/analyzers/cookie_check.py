from typing import List
import httpx
from app.schemas.report import Finding, Severity

def analyze_cookies(response: httpx.Response) -> List[Finding]:
    """
    Analyzes Set-Cookie headers for security attributes.
    """
    findings = []
    cookies = response.cookies

    if not cookies:
        # We don't report missing cookies as a vulnerability,
        # as not using cookies is actually more secure.
        return findings

    for cookie_name, cookie_value in cookies.items():
        # Note: httpx's Cookie object stores attributes.
        # However, cookies are often received via the 'Set-Cookie' header.
        # Let's inspect the raw Set-Cookie headers for attributes.
        pass

    # Better approach: Inspect raw 'Set-Cookie' headers
    raw_cookies = response.headers.get_list("set-cookie")

    for cookie_header in raw_cookies:
        # Example: "session=123; HttpOnly; Secure; SameSite=Lax"
        parts = [p.strip().lower() for p in cookie_header.split(";")]

        # 1. HttpOnly check
        if "httponly" not in parts:
            findings.append(Finding(
                id="COOKIE_MISSING_HTTPONLY",
                title="Cookie Missing HttpOnly Attribute",
                severity=Severity.MEDIUM,
                evidence=f"Cookie: {cookie_header.split(';')[0]}",
                explanation="Cookies without HttpOnly can be accessed by JavaScript, increasing XSS risk.",
                remediation="Add the HttpOnly attribute to all sensitive cookies."
            ))

        # 2. Secure check
        if "secure" not in parts:
            findings.append(Finding(
                id="COOKIE_MISSING_SECURE",
                title="Cookie Missing Secure Attribute",
                severity=Severity.MEDIUM,
                evidence=f"Cookie: {cookie_header.split(';')[0]}",
                explanation="Cookies without the Secure attribute can be sent over unencrypted HTTP.",
                remediation="Add the Secure attribute to all cookies."
            ))

        # 3. SameSite check
        if not any("samesite" in p for p in parts):
            findings.append(Finding(
                id="COOKIE_MISSING_SAMESITE",
                title="Cookie Missing SameSite Attribute",
                severity=Severity.LOW,
                evidence=f"Cookie: {cookie_header.split(';')[0]}",
                explanation="SameSite attribute helps protect against CSRF attacks.",
                remediation="Set SameSite attribute to 'Lax' or 'Strict'."
            ))

    return findings
