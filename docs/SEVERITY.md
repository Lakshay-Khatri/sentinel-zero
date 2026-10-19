# Sentinel Zero — Severity Rules

This document lists every finding Sentinel Zero can report, the severity it
gets, and why. It is the reference for the analyzers in
`backend/app/analyzers/`. A test (`backend/tests/test_severity_doc.py`) checks
that every finding ID in the code appears here with the same severity, so the
document cannot silently go out of date.

## 1. What the severity levels mean

Sentinel Zero is a **passive** scanner: it makes one normal HTTPS request and
inspects what comes back. It never tries to exploit anything. Severity therefore
describes **how much protection is missing**, not proof that a site can be
attacked.

| Level | Meaning | Typical example |
|---|---|---|
| `critical` | **Not used.** Reserved for issues that are directly exploitable with no further conditions. A passive scan cannot confirm exploitability, so it never assigns this level. | — |
| `high` | Traffic is not protected by trustworthy encryption at all. | Site only serves plain HTTP; certificate fails verification |
| `medium` | A main defence against a common attack (XSS, SSL stripping, session theft) is missing or switched off. | No `Content-Security-Policy`; session cookie without `HttpOnly` |
| `low` | A defence exists but is weakened or misconfigured, or a defence-in-depth control is missing. | HSTS `max-age` under one year; missing `X-Content-Type-Options` |
| `info` | Good-practice hardening with limited direct risk, or a note about scan limits. | Missing `Referrer-Policy`; TLS details unavailable |

These are qualitative levels chosen for this project. They are **not** CVSS
scores.

## 2. General rules

1. **Absent, empty and weak are separate states.** A missing header gives
   `MISSING_<X>`, an empty one gives `<X>_EMPTY` (same severity, since it
   protects nothing), and a present-but-weak value gets its own ID.
2. **Evidence shows what was observed.** Header evidence shows the actual
   header (cut off at 300 characters). Cookie evidence shows the cookie name and
   attributes but **never the cookie value**, because it may be a secret.
3. **Context lowers severity where the risk is lower.** For example, a missing
   `X-Frame-Options` is not reported when CSP `frame-ancestors` is set, and
   cookie severity depends on whether the cookie looks like a login cookie.
4. **Browsers' real behaviour wins.** Values that browsers ignore (an invalid
   `SameSite`, an `X-Frame-Options` with conflicting values) are treated as
   giving no protection.
5. **One finding per problem.** CSP issues are grouped so each ID appears at
   most once per scan, with every affected directive listed in the evidence.
   Cookie findings are per cookie, so the same ID can appear once per cookie.

## 3. TLS / HTTPS findings (`ssl_check.py`)

| ID | Severity | Reported when | Why this severity |
|---|---|---|---|
| `NO_HTTPS` | `high` | An `http://` URL is served without redirecting to HTTPS. | All traffic, including passwords and cookies, travels unencrypted. |
| `CERT_VERIFICATION_FAILED` | `high` | The certificate is expired, self-signed, untrusted, or for the wrong hostname. | Browsers block the page; users who click through cannot detect an attacker in the middle. |
| `CERT_EXPIRING_SOON` | `medium` / `low` | The certificate expires in 14 days or less (`medium`) or 30 days or less (`low`). | An imminent outage; more urgent the closer the date. |
| `HTTP_REDIRECTS_TO_HTTPS` | `low` | An `http://` URL redirects to `https://`. | Good behaviour, but the first request is still unencrypted (fixable with HSTS). |
| `TLS_DETAILS_UNAVAILABLE` | `info` | The connection was verified, but the certificate could not be read. | A scan limitation, not a site problem. |

**Limitation:** a passive scan sees only the one TLS version and cipher that
were negotiated. It cannot list every version the server supports, so there
is no "old TLS version" finding.

## 4. HTTP security header findings (`header_check.py`)

| ID | Severity | Reported when | Why this severity |
|---|---|---|---|
| `MISSING_CSP` | `medium` | No `Content-Security-Policy` header. | CSP is the main browser-side defence against XSS. |
| `CSP_EMPTY` | `medium` | CSP header present but empty. | Same as missing. |
| `CSP_WILDCARD` | `medium` | `*` in `default-src` or `script-src`. | Allows scripts from any domain, defeating CSP's purpose. |
| `CSP_UNSAFE_EVAL` | `medium` | `'unsafe-eval'` in any directive. | Re-enables `eval()`, a common XSS path. |
| `CSP_UNSAFE_INLINE` | `low` | `'unsafe-inline'` without a nonce or hash in that directive. | Weakens CSP, but other directives may still help. Not reported when a nonce/hash is present, because browsers then ignore it. |
| `MISSING_HSTS` | `medium` | No `Strict-Transport-Security` header. | Allows SSL-stripping (downgrade to HTTP) attacks. |
| `HSTS_EMPTY` | `medium` | HSTS header present but empty. | Same as missing. |
| `HSTS_MALFORMED` | `medium` | No valid `max-age` in the header. | Browsers ignore the header, so it is the same as missing. |
| `HSTS_DISABLED` | `medium` | `max-age=0`. | Tells browsers to forget HSTS, so it is the same as missing. |
| `HSTS_WEAK` | `low` | `max-age` below 31,536,000 seconds (1 year). | Protection exists but expires sooner than recommended. |
| `MISSING_XCTO` | `low` | No `X-Content-Type-Options` header. | Defence in depth against MIME-sniffing attacks. |
| `XCTO_EMPTY` | `low` | Header present but empty. | Same as missing. |
| `XCTO_INVALID` | `low` | Value is not `nosniff`. | Browsers ignore other values. |
| `MISSING_XFO` | `low` | No `X-Frame-Options` **and** no CSP `frame-ancestors`. | Clickjacking protection missing; only matters for pages with sensitive actions. |
| `XFO_EMPTY` | `low` | Header present but empty. | Same as missing. |
| `XFO_INVALID` | `low` | Value is not a single `DENY`/`SAMEORIGIN` (includes conflicting duplicates). | Browsers ignore it, leaving the page frameable. |
| `MISSING_RP` | `info` | No `Referrer-Policy` header. | Modern browsers already default to `strict-origin-when-cross-origin`. |
| `RP_EMPTY` | `info` | Header present but empty. | Same as missing. |
| `RP_INVALID` | `info` | No recognised policy value. | Browser falls back to its (reasonable) default. |
| `RP_UNSAFE_URL` | `low` | Effective policy is `unsafe-url`. | Actively leaks full URLs (paths, query strings) to every site, which is worse than the default. |

## 5. Cookie findings (`cookie_check.py`)

A passive scanner cannot know what a cookie stores, so it guesses from the
cookie name. A cookie is treated as **sensitive** if its name contains any of:
`sess`, `sid`, `auth`, `token`, `jwt`, `login`, `remember`, `identity`
(case-insensitive). This is a heuristic, and the finding text says so.
Deletion cookies (`Max-Age<=0` or an `Expires` date in the past) are skipped.

| ID | Severity | Reported when | Why this severity |
|---|---|---|---|
| `COOKIE_MISSING_HTTPONLY` | `medium` (sensitive) / `low` (other) | No `HttpOnly` attribute. | A sensitive cookie readable by JavaScript can be stolen through XSS. Other cookies are often *meant* to be read by scripts. |
| `COOKIE_MISSING_SECURE` | `medium` (sensitive) / `low` (other) | No `Secure` attribute. | The cookie can be sent over plain HTTP and intercepted. |
| `COOKIE_MISSING_SAMESITE` | `low` (sensitive) / `info` (other) | No `SameSite` attribute. | CSRF defence. Some browsers default to `Lax`, so the risk is partly reduced. |
| `COOKIE_SAMESITE_INVALID` | `info` | `SameSite` is not `Strict`, `Lax` or `None`. | Browsers ignore it and use their default. |
| `COOKIE_SAMESITE_NONE_INSECURE` | `low` | `SameSite=None` without `Secure`. | Modern browsers reject the cookie; older ones send it cross-site over HTTP. |
| `COOKIE_PREFIX_INVALID` | `low` | A `__Host-` or `__Secure-` cookie breaks its prefix rules. | Browsers reject the cookie, so its intended protection is lost. |

## 6. References

- OWASP Secure Headers Project — https://owasp.org/www-project-secure-headers/
- MDN Web Docs, HTTP headers — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
- RFC 6797, HTTP Strict Transport Security — https://www.rfc-editor.org/rfc/rfc6797
- RFC 6265, HTTP State Management (cookies) — https://www.rfc-editor.org/rfc/rfc6265
  (cookie prefixes and `SameSite` are specified in the RFC 6265bis draft)
- W3C Content Security Policy Level 3 — https://www.w3.org/TR/CSP3/
- W3C Referrer Policy — https://www.w3.org/TR/referrer-policy/

## 7. Changing a rule

1. Change the analyzer code.
2. Update the matching row in this document.
3. Run `python -m pytest tests -v` from `backend/`. `test_severity_doc.py`
   fails if this document and the code disagree.

Finding IDs are part of the API: once published, an ID should not be renamed.
