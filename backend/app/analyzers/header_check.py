from typing import List
import httpx
from app.schemas.report import Finding, Severity

# Define the headers we check and their security significance
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "id": "MISSING_CSP",
        "title": "Missing Content-Security-Policy",
        "severity": Severity.MEDIUM,
        "explanation": "CSP helps prevent XSS by restricting where resources can be loaded from.",
        "remediation": "Implement a strict Content-Security-Policy header."
    },
    "Strict-Transport-Security": {
        "id": "MISSING_HSTS",
        "title": "Missing Strict-Transport-Security",
        "severity": Severity.MEDIUM,
        "explanation": "HSTS forces browsers to use HTTPS, preventing SSL stripping attacks.",
        "remediation": "Implement the Strict-Transport-Security header with a long max-age."
    },
    "X-Content-Type-Options": {
        "id": "MISSING_XCTO",
        "title": "Missing X-Content-Type-Options",
        "severity": Severity.LOW,
        "explanation": "This header prevents the browser from 'sniffing' the MIME type.",
        "remediation": "Set X-Content-Type-Options to 'nosniff'."
    },
    "X-Frame-Options": {
        "id": "MISSING_XFO",
        "title": "Missing X-Frame-Options",
        "severity": Severity.LOW,
        "explanation": "X-Frame-Options prevents the site from being embedded in an iframe (Clickjacking).",
        "remediation": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'."
    },
    "Referrer-Policy": {
        "id": "MISSING_RP",
        "title": "Missing Referrer-Policy",
        "severity": Severity.INFO,
        "explanation": "Referrer-Policy controls how much referrer information is passed.",
        "remediation": "Implement a Referrer-Policy header (e.g., 'strict-origin-when-cross-origin')."
    }
}

from typing import List
import httpx
from app.schemas.report import Finding, Severity

# Define the headers we check and their security significance
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "id": "MISSING_CSP",
        "title": "Missing Content-Security-Policy",
        "severity": Severity.MEDIUM,
        "explanation": "CSP helps prevent XSS by restricting where resources can be loaded from.",
        "remediation": "Implement a strict Content-Security-Policy header."
    },
    "Strict-Transport-Security": {
        "id": "MISSING_HSTS",
        "title": "Missing Strict-Transport-Security",
        "severity": Severity.MEDIUM,
        "explanation": "HSTS forces browsers to use HTTPS, preventing SSL stripping attacks.",
        "remediation": "Implement the Strict-Transport-Security header with a long max-age."
    },
    "X-Content-Type-Options": {
        "id": "MISSING_XCTO",
        "title": "Missing X-Content-Type-Options",
        "severity": Severity.LOW,
        "explanation": "This header prevents the browser from 'sniffing' the MIME type.",
        "remediation": "Set X-Content-Type-Options to 'nosniff'."
    },
    "X-Frame-Options": {
        "id": "MISSING_XFO",
        "title": "Missing X-Frame-Options",
        "severity": Severity.LOW,
        "explanation": "X-Frame-Options prevents the site from being embedded in an iframe (Clickjacking).",
        "remediation": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'."
    },
    "Referrer-Policy": {
        "id": "MISSING_RP",
        "title": "Missing Referrer-Policy",
        "severity": Severity.INFO,
        "explanation": "Referrer-Policy controls how much referrer information is passed.",
        "remediation": "Implement a Referrer-Policy header (e.g., 'strict-origin-when-cross-origin')."
    }
}

def analyze_headers(response: httpx.Response) -> List[Finding]:
    """
    Analyzes HTTP response headers for security gaps, including value validation.
    """
    findings = []
    headers = response.headers

    for header, info in SECURITY_HEADERS.items():
        value = headers.get(header)
        if value is None:
            findings.append(Finding(
                id=info["id"],
                title=info["title"],
                severity=info["severity"],
                evidence="Header missing",
                explanation=info["explanation"],
                remediation=info["remediation"]
            ))
            continue

        # Value Validation
        if header == "Strict-Transport-Security":
            findings.extend(_validate_hsts(value))
        elif header == "Content-Security-Policy":
            findings.extend(_validate_csp(value))
        elif header == "X-Frame-Options":
            findings.extend(_validate_xfo(value))

    return findings

def _validate_hsts(value: str) -> List[Finding]:
    findings = []
    # HSTS format: max-age=SECONDS; includeSubDomains; preload
    parts = [p.strip().lower() for p in value.split(";")]
    max_age_val = None

    for part in parts:
        if part.startswith("max-age="):
            try:
                max_age_val = int(part.split("=")[1])
            except (ValueError, IndexError):
                pass

    if max_age_val is None:
        findings.append(Finding(
            id="HSTS_MALFORMED",
            title="Malformed HSTS Header",
            severity=Severity.MEDIUM,
            evidence=value,
            explanation="The HSTS header is present but missing a valid max-age directive.",
            remediation="Ensure HSTS is configured as 'max-age=31536000'."
        ))
    elif max_age_val < 31536000:
        findings.append(Finding(
            id="HSTS_WEAK",
            title="Weak HSTS Policy",
            severity=Severity.LOW,
            evidence=f"max-age={max_age_val}",
            explanation="The HSTS max-age is shorter than the recommended 1 year (31,536,000 seconds).",
            remediation="Increase max-age to at least 31536000 seconds."
        ))
    return findings

def _validate_csp(value: str) -> List[Finding]:
    findings = []
    # CSP format: directive1 val1 val2; directive2 val1
    directives = [d.strip() for d in value.split(";")]

    for directive in directives:
        if not directive:
            continue

        parts = directive.split()
        name = parts[0].lower()
        values = [v.lower() for v in parts[1:]]

        # Check for dangerous patterns
        if name == "default-src" and "*" in values:
            findings.append(Finding(
                id="CSP_WILDCARD",
                title="Permissive CSP Default Source",
                severity=Severity.MEDIUM,
                evidence="default-src *",
                explanation="Using a wildcard in default-src allows loading resources from any domain, weakening XSS protections.",
                remediation="Restrict default-src to trusted domains or 'self'."
            ))

        # We check for unsafe-eval in ANY directive, not just script-src
        if any("unsafe-eval" in v for v in values):
            findings.append(Finding(
                id="CSP_UNSAFE_EVAL",
                title="CSP Allows unsafe-eval",
                severity=Severity.MEDIUM,
                evidence="unsafe-eval",
                explanation="The 'unsafe-eval' keyword allows the use of eval() and similar functions, which can be exploited for XSS.",
                remediation="Remove 'unsafe-eval' from your CSP directives."
            ))

        if any("unsafe-inline" in v for v in values):
            findings.append(Finding(
                id="CSP_UNSAFE_INLINE",
                title="CSP Allows unsafe-inline",
                severity=Severity.LOW,
                evidence="unsafe-inline",
                explanation="The 'unsafe-inline' keyword allows inline scripts and styles, increasing XSS risk.",
                remediation="Use nonces or hashes instead of 'unsafe-inline'."
            ))

    return findings

def _validate_xfo(value: str) -> List[Finding]:
    findings = []
    val_upper = value.upper()
    if val_upper not in ("DENY", "SAMEORIGIN"):
        findings.append(Finding(
            id="XFO_INVALID",
            title="Invalid X-Frame-Options Value",
            severity=Severity.LOW,
            evidence=value,
            explanation="X-Frame-Options should be set to 'DENY' or 'SAMEORIGIN'.",
            remediation="Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'."
        ))
    return findings
