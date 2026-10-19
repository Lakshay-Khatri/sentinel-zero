"""
HTTP security-header analyzer.

Each header can be in one of four states, and each state gets its own finding:
  1. absent              -> MISSING_<X>   (severity from SECURITY_HEADERS)
  2. present but empty   -> <X>_EMPTY     (same severity as missing: it protects nothing)
  3. present but weak    -> header-specific IDs (HSTS_WEAK, CSP_UNSAFE_INLINE, ...)
  4. present and sound   -> no finding

Severity guide used here:
  MEDIUM - a missing/disabled control against a common attack (XSS, SSL stripping)
  LOW    - a weaker or misconfigured value, or a defence-in-depth header
  INFO   - good-practice hardening with limited direct risk
"""
from typing import List, Optional
import httpx
from app.schemas.report import Finding, Severity

# Long header values (CSP can be several KB) are shortened in evidence.
MAX_EVIDENCE_LEN = 300

ONE_YEAR_SECONDS = 31536000

# Define the headers we check and their security significance
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "id": "MISSING_CSP",
        "prefix": "CSP",
        "title": "Missing Content-Security-Policy",
        "severity": Severity.MEDIUM,
        "explanation": "CSP helps prevent XSS by restricting where resources can be loaded from.",
        "remediation": "Implement a strict Content-Security-Policy header."
    },
    "Strict-Transport-Security": {
        "id": "MISSING_HSTS",
        "prefix": "HSTS",
        "title": "Missing Strict-Transport-Security",
        "severity": Severity.MEDIUM,
        "explanation": "HSTS forces browsers to use HTTPS, preventing SSL stripping attacks.",
        "remediation": "Implement the Strict-Transport-Security header with a long max-age."
    },
    "X-Content-Type-Options": {
        "id": "MISSING_XCTO",
        "prefix": "XCTO",
        "title": "Missing X-Content-Type-Options",
        "severity": Severity.LOW,
        "explanation": "This header prevents the browser from 'sniffing' the MIME type.",
        "remediation": "Set X-Content-Type-Options to 'nosniff'."
    },
    "X-Frame-Options": {
        "id": "MISSING_XFO",
        "prefix": "XFO",
        "title": "Missing X-Frame-Options",
        "severity": Severity.LOW,
        "explanation": "X-Frame-Options prevents the site from being embedded in an iframe (Clickjacking).",
        "remediation": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN', or use the CSP 'frame-ancestors' directive."
    },
    "Referrer-Policy": {
        "id": "MISSING_RP",
        "prefix": "RP",
        "title": "Missing Referrer-Policy",
        "severity": Severity.INFO,
        "explanation": "Referrer-Policy controls how much referrer information is passed.",
        "remediation": "Implement a Referrer-Policy header (e.g., 'strict-origin-when-cross-origin')."
    }
}

# Referrer-Policy tokens defined by the W3C spec.
_REFERRER_POLICY_TOKENS = {
    "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
    "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url",
}


def _evidence(header: str, value: str) -> str:
    """Format an observed header as evidence, shortening very long values."""
    if len(value) > MAX_EVIDENCE_LEN:
        value = value[:MAX_EVIDENCE_LEN] + "... (truncated)"
    return f"{header}: {value}"


def analyze_headers(response: httpx.Response) -> List[Finding]:
    """
    Analyzes HTTP response headers for security gaps, including value validation.
    """
    findings = []
    # httpx.Headers is case-insensitive and keeps repeated headers separately.
    headers = httpx.Headers(response.headers)
    csp_values = headers.get_list("Content-Security-Policy")

    for header, info in SECURITY_HEADERS.items():
        values = headers.get_list(header)

        if not values:
            # CSP frame-ancestors is the modern replacement for X-Frame-Options,
            # so a missing XFO is not a gap when frame-ancestors is set.
            if header == "X-Frame-Options" and _csp_has_frame_ancestors(csp_values):
                continue
            findings.append(Finding(
                id=info["id"],
                title=info["title"],
                severity=info["severity"],
                evidence="Header missing",
                explanation=info["explanation"],
                remediation=info["remediation"]
            ))
            continue

        if all(not v.strip() for v in values):
            findings.append(Finding(
                id=f"{info['prefix']}_EMPTY",
                title=f"Empty {header} Header",
                severity=info["severity"],
                evidence=f"{header} is present but has an empty value",
                explanation=f"The header is sent without a value, so it provides no protection. {info['explanation']}",
                remediation=info["remediation"]
            ))
            continue

        # Value Validation
        if header == "Strict-Transport-Security":
            findings.extend(_validate_hsts(values))
        elif header == "Content-Security-Policy":
            findings.extend(_validate_csp(values))
        elif header == "X-Frame-Options":
            findings.extend(_validate_xfo(values))
        elif header == "X-Content-Type-Options":
            findings.extend(_validate_xcto(values))
        elif header == "Referrer-Policy":
            findings.extend(_validate_referrer_policy(values))

    return findings


def _parse_max_age(value: str) -> Optional[int]:
    """Return the HSTS max-age in seconds, or None if missing/invalid."""
    for part in value.split(";"):
        name, _, raw = part.strip().partition("=")
        if name.strip().lower() == "max-age":
            # RFC 6797 allows the value to be a quoted string.
            raw = raw.strip().strip('"')
            if raw.isdigit():
                return int(raw)
            return None
    return None


def _validate_hsts(values: List[str]) -> List[Finding]:
    findings = []
    # Browsers only process the first HSTS header (RFC 6797, section 8.1).
    value = values[0]
    evidence = _evidence("Strict-Transport-Security", value)
    max_age_val = _parse_max_age(value)

    if max_age_val is None:
        findings.append(Finding(
            id="HSTS_MALFORMED",
            title="Malformed HSTS Header",
            severity=Severity.MEDIUM,
            evidence=evidence,
            explanation="The HSTS header is present but missing a valid max-age directive, so browsers ignore it.",
            remediation="Ensure HSTS is configured as 'max-age=31536000'."
        ))
    elif max_age_val == 0:
        findings.append(Finding(
            id="HSTS_DISABLED",
            title="HSTS Disabled (max-age=0)",
            severity=Severity.MEDIUM,
            evidence=evidence,
            explanation="max-age=0 instructs browsers to forget any stored HSTS policy, so HTTPS is no longer enforced.",
            remediation="Set max-age to at least 31536000 seconds (1 year)."
        ))
    elif max_age_val < ONE_YEAR_SECONDS:
        findings.append(Finding(
            id="HSTS_WEAK",
            title="Weak HSTS Policy",
            severity=Severity.LOW,
            evidence=evidence,
            explanation="The HSTS max-age is shorter than the recommended 1 year (31,536,000 seconds).",
            remediation="Increase max-age to at least 31536000 seconds."
        ))
    return findings


def _parse_csp(policy: str) -> dict:
    """Parse one CSP policy into {directive_name: [lowercased source values]}."""
    directives = {}
    for directive in policy.split(";"):
        parts = directive.split()
        if not parts:
            continue
        name = parts[0].lower()
        # Per the CSP spec, a repeated directive is ignored after its first occurrence.
        directives.setdefault(name, [v.lower() for v in parts[1:]])
    return directives


def _csp_has_frame_ancestors(csp_values: List[str]) -> bool:
    return any("frame-ancestors" in _parse_csp(policy) for policy in csp_values)


def _validate_csp(values: List[str]) -> List[Finding]:
    findings = []
    wildcard, unsafe_eval, unsafe_inline = [], [], []

    # Each CSP header is a separate policy; parse them one by one.
    for policy in values:
        for name, sources in _parse_csp(policy).items():
            if name in ("default-src", "script-src") and "*" in sources:
                wildcard.append(f"{name} *")

            if "'unsafe-eval'" in sources:
                unsafe_eval.append(f"{name} 'unsafe-eval'")

            if "'unsafe-inline'" in sources:
                # Browsers ignore 'unsafe-inline' when a nonce or hash is also listed.
                neutralised = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                                  for s in sources)
                if not neutralised:
                    unsafe_inline.append(f"{name} 'unsafe-inline'")

    # One finding per issue type; evidence lists every directive affected.
    if wildcard:
        findings.append(Finding(
            id="CSP_WILDCARD",
            title="Permissive CSP Source Wildcard",
            severity=Severity.MEDIUM,
            evidence="; ".join(wildcard),
            explanation="A wildcard in default-src or script-src allows loading scripts from any domain, weakening XSS protections.",
            remediation="Restrict default-src and script-src to 'self' and specific trusted domains."
        ))

    if unsafe_eval:
        findings.append(Finding(
            id="CSP_UNSAFE_EVAL",
            title="CSP Allows unsafe-eval",
            severity=Severity.MEDIUM,
            evidence="; ".join(unsafe_eval),
            explanation="The 'unsafe-eval' keyword allows the use of eval() and similar functions, which can be exploited for XSS.",
            remediation="Remove 'unsafe-eval' from your CSP directives."
        ))

    if unsafe_inline:
        findings.append(Finding(
            id="CSP_UNSAFE_INLINE",
            title="CSP Allows unsafe-inline",
            severity=Severity.LOW,
            evidence="; ".join(unsafe_inline),
            explanation="The 'unsafe-inline' keyword allows inline scripts and styles, increasing XSS risk.",
            remediation="Use nonces or hashes instead of 'unsafe-inline'."
        ))

    return findings


def _validate_xfo(values: List[str]) -> List[Finding]:
    # Multiple headers (or a comma-joined value) are only valid if all agree.
    tokens = {t.strip().upper() for v in values for t in v.split(",") if t.strip()}
    if len(tokens) == 1 and tokens <= {"DENY", "SAMEORIGIN"}:
        return []
    return [Finding(
        id="XFO_INVALID",
        title="Invalid X-Frame-Options Value",
        severity=Severity.LOW,
        evidence=_evidence("X-Frame-Options", ", ".join(values)),
        explanation="X-Frame-Options should be a single 'DENY' or 'SAMEORIGIN'. Other or conflicting values are ignored by browsers, leaving the page frameable.",
        remediation="Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'."
    )]


def _validate_xcto(values: List[str]) -> List[Finding]:
    # 'nosniff' is the only defined value; browsers check the first one.
    if values[0].split(",")[0].strip().lower() == "nosniff":
        return []
    return [Finding(
        id="XCTO_INVALID",
        title="Invalid X-Content-Type-Options Value",
        severity=Severity.LOW,
        evidence=_evidence("X-Content-Type-Options", ", ".join(values)),
        explanation="The only valid value is 'nosniff'. Any other value is ignored, so MIME sniffing stays enabled.",
        remediation="Set X-Content-Type-Options to 'nosniff'."
    )]


def _validate_referrer_policy(values: List[str]) -> List[Finding]:
    # The policy may be a comma-separated list; the last recognised token wins.
    tokens = [t.strip().lower() for v in values for t in v.split(",") if t.strip()]
    effective = next((t for t in reversed(tokens) if t in _REFERRER_POLICY_TOKENS), None)
    evidence = _evidence("Referrer-Policy", ", ".join(values))

    if effective is None:
        return [Finding(
            id="RP_INVALID",
            title="Invalid Referrer-Policy Value",
            severity=Severity.INFO,
            evidence=evidence,
            explanation="No recognised policy value was found, so the browser falls back to its default referrer behaviour.",
            remediation="Use a valid value such as 'strict-origin-when-cross-origin' or 'no-referrer'."
        )]
    if effective == "unsafe-url":
        return [Finding(
            id="RP_UNSAFE_URL",
            title="Referrer-Policy Leaks Full URLs",
            severity=Severity.LOW,
            evidence=evidence,
            explanation="'unsafe-url' sends the full URL (including path and query string) to every site, even over plain HTTP. Tokens or personal data in URLs can leak.",
            remediation="Use 'strict-origin-when-cross-origin' or a stricter policy."
        )]
    return []
