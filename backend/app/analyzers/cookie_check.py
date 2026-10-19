"""
Cookie security analyzer.

Each raw Set-Cookie header is parsed and checked on its own. Cookie values are
never copied into findings, because they may be session tokens or other secrets.

A passive scan cannot know what a cookie is used for, so severity depends on a
name-based guess: cookies whose name looks like a session/auth cookie are
"sensitive" and get a higher severity than e.g. a theme-preference cookie.

Severity guide:
  MEDIUM - sensitive-looking cookie missing HttpOnly or Secure
  LOW    - other cookies missing HttpOnly/Secure; sensitive cookie missing SameSite;
           cookies browsers will reject (SameSite=None without Secure, bad prefix)
  INFO   - non-sensitive cookie missing SameSite; unrecognised SameSite value
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Dict, List
import httpx
from app.schemas.report import Finding, Severity

# Name fragments that suggest a cookie carries a session or login credential.
SENSITIVE_NAME_HINTS = ("sess", "sid", "auth", "token", "jwt", "login", "remember", "identity")

_VALID_SAMESITE = {"strict", "lax", "none"}


@dataclass
class ParsedCookie:
    name: str
    # Attribute names are lowercased; the last occurrence wins, as in browsers.
    attributes: Dict[str, str] = field(default_factory=dict)

    def has(self, attr: str) -> bool:
        return attr in self.attributes


def parse_set_cookie(header: str) -> ParsedCookie:
    """Parse one Set-Cookie header value (RFC 6265 section 5.2)."""
    name_value, *attr_parts = header.split(";")
    name = name_value.split("=", 1)[0].strip() if "=" in name_value else ""
    attributes = {}
    for part in attr_parts:
        attr_name, _, attr_value = part.partition("=")
        attr_name = attr_name.strip().lower()
        if attr_name:
            attributes[attr_name] = attr_value.strip()
    return ParsedCookie(name=name, attributes=attributes)


def _is_sensitive(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in SENSITIVE_NAME_HINTS)


def _is_deletion(cookie: ParsedCookie) -> bool:
    """A cookie with Max-Age<=0 or an Expires date in the past is being deleted."""
    max_age = cookie.attributes.get("max-age")
    if max_age is not None:
        try:
            return int(max_age) <= 0
        except ValueError:
            pass
    expires = cookie.attributes.get("expires")
    if expires:
        try:
            # Servers often write "01-Jan-1970"; the parser expects spaces.
            return parsedate_to_datetime(expires.replace("-", " ")) < datetime.now(timezone.utc)
        except (TypeError, ValueError):
            pass
    return False


def _evidence(cookie: ParsedCookie) -> str:
    """Describe the cookie without revealing its value."""
    shown = []
    for attr, value in cookie.attributes.items():
        shown.append(f"{attr}={value}" if value else attr)
    attrs = "; ".join(shown) if shown else "none"
    return f"Cookie '{cookie.name or '(unnamed)'}' (value hidden) - attributes: {attrs}"


def analyze_cookies(response: httpx.Response) -> List[Finding]:
    """
    Analyzes Set-Cookie headers for security attributes.
    """
    findings = []
    # Read the raw headers: httpx's cookie jar silently drops cookies it would
    # not store (e.g. Domain mismatch), which would hide them from the scan.
    for raw in response.headers.get_list("set-cookie"):
        if not raw.strip():
            continue
        cookie = parse_set_cookie(raw)
        if _is_deletion(cookie):
            continue
        findings.extend(_check_cookie(cookie))
    return findings


def _check_cookie(cookie: ParsedCookie) -> List[Finding]:
    findings = []
    sensitive = _is_sensitive(cookie.name)
    evidence = _evidence(cookie)
    context = (
        "The cookie name suggests it may hold a session or login credential."
        if sensitive else
        "The cookie name does not suggest a session credential, so the impact is likely lower; "
        "confirm what this cookie stores."
    )

    # 1. HttpOnly check
    if not cookie.has("httponly"):
        findings.append(Finding(
            id="COOKIE_MISSING_HTTPONLY",
            title="Cookie Missing HttpOnly Attribute",
            severity=Severity.MEDIUM if sensitive else Severity.LOW,
            evidence=evidence,
            explanation="Cookies without HttpOnly can be read by JavaScript, so an XSS bug could steal them. " + context,
            remediation="Add HttpOnly to cookies that page scripts do not need to read, especially session cookies."
        ))

    # 2. Secure check
    if not cookie.has("secure"):
        findings.append(Finding(
            id="COOKIE_MISSING_SECURE",
            title="Cookie Missing Secure Attribute",
            severity=Severity.MEDIUM if sensitive else Severity.LOW,
            evidence=evidence,
            explanation="Cookies without the Secure attribute can be sent over unencrypted HTTP, where they can be intercepted. " + context,
            remediation="Add the Secure attribute to all cookies on HTTPS sites."
        ))

    # 3. SameSite checks
    samesite = cookie.attributes.get("samesite")
    if samesite is None:
        findings.append(Finding(
            id="COOKIE_MISSING_SAMESITE",
            title="Cookie Missing SameSite Attribute",
            severity=Severity.LOW if sensitive else Severity.INFO,
            evidence=evidence,
            explanation="SameSite limits when cookies are sent on cross-site requests, which helps against CSRF. "
                        "Some browsers default to Lax, but others do not, so behaviour is inconsistent.",
            remediation="Set SameSite explicitly to 'Lax' or 'Strict'."
        ))
    elif samesite.lower() not in _VALID_SAMESITE:
        findings.append(Finding(
            id="COOKIE_SAMESITE_INVALID",
            title="Invalid SameSite Value",
            severity=Severity.INFO,
            evidence=evidence,
            explanation="Only 'Strict', 'Lax' and 'None' are valid. Browsers ignore other values and fall back to their default.",
            remediation="Set SameSite to 'Lax' or 'Strict'."
        ))
    elif samesite.lower() == "none" and not cookie.has("secure"):
        findings.append(Finding(
            id="COOKIE_SAMESITE_NONE_INSECURE",
            title="SameSite=None Without Secure",
            severity=Severity.LOW,
            evidence=evidence,
            explanation="Modern browsers reject SameSite=None cookies that lack the Secure attribute; "
                        "older browsers would send them cross-site over plain HTTP.",
            remediation="Add the Secure attribute, or use SameSite=Lax if cross-site use is not needed."
        ))

    # 4. Cookie prefix rules (RFC 6265bis): browsers reject cookies that break them.
    lowered_name = cookie.name.lower()
    prefix_problem = None
    if lowered_name.startswith("__host-"):
        if not cookie.has("secure") or cookie.has("domain") or cookie.attributes.get("path") != "/":
            prefix_problem = "__Host- cookies must have Secure, Path=/ and no Domain attribute."
    elif lowered_name.startswith("__secure-") and not cookie.has("secure"):
        prefix_problem = "__Secure- cookies must have the Secure attribute."
    if prefix_problem:
        findings.append(Finding(
            id="COOKIE_PREFIX_INVALID",
            title="Cookie Prefix Requirements Not Met",
            severity=Severity.LOW,
            evidence=evidence,
            explanation=f"{prefix_problem} Browsers reject cookies that break these rules, so the intended protection is lost.",
            remediation="Add the attributes required by the cookie's prefix."
        ))

    return findings
