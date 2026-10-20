# Sentinel Zero — Testing

This document explains how Sentinel Zero is tested and records the results of
the integration test run on **2026-10-19** (Windows 11, Python 3.14.5).

## 1. How to run the tests

All commands are for Windows PowerShell, starting in the `sentinel-zero` folder.

**Backend unit and API tests** (offline, about 10 seconds):

```powershell
cd backend
python -m pytest -v
```

**Live tests** (need internet; real websites are scanned), also in `backend`:

```powershell
python -m pytest -m live -v
```

**Frontend build and lint**, from the `sentinel-zero` folder:

```powershell
cd backend\frontend
npm run build
npm run lint
```

## 2. What the automated tests cover

| File | Tests | What it checks |
|---|---|---|
| `test_validator.py` | 16 | URL parsing, credentials, ports, DNS results, mixed public/private DNS answers |
| `test_ssrf.py` | 56 | DNS rebinding against a real loopback server, proxy hijacking, 24 private/special IP addresses (plus 2 invalid strings), unusual IP notations, the port allow-list, the shared connect timeout |
| `test_analyzers.py` | 48 | Header, cookie and TLS analyzers including edge cases; HTTP client behaviour (gzip bombs, corrupt bodies, redirects, certificate errors) |
| `test_api.py` | 15 | `/health`, `/scan`, certificate-failure reports, rate limiting (incl. the trusted proxy IP header and resistance to faked headers), concurrency limit, CORS, URL length, error logging without leaks, security headers on API responses, and that Sentinel Zero's own analyzer finds no header issues in its API |
| `test_severity_doc.py` | 5 | `docs/SEVERITY.md` lists every finding ID with the same severity as the code |
| `test_live.py` | 7 | Opt-in: real scans of public sites (skipped by default) |

**Design rules for the default test run**
- It must not depend on the internet. A network audit on 2026-10-19 found and
  fixed two tests that made real connections. The only remaining lookups are
  for IP-literal notations (e.g. `0x7f.0.0.1`), which are rejected whether or
  not the lookup succeeds.
- SSRF tests use a real HTTP server on `127.0.0.1` to stand in for an internal
  service, and assert that it received **no** request.
- Every security regression test was checked to **fail on the code before the
  fix** and pass after it.

**Result:** 135 passed, 7 live tests deselected, at the time of the
integration run. The suite was run 3 times in a row with identical results.
Deployment preparation later added 5 API tests (140 in total).

## 3. Live API integration results (2026-10-19)

Run against a local backend (`python -m uvicorn app.main:app`), with the rate
limit raised for the duration of the matrix.

| Group | Target | Result |
|---|---|---|
| Real site | `https://example.com` | 200: 5 findings, TLSv1.3 |
| Real site | `https://github.com` | 200: 2 findings, TLSv1.3 |
| Real site | `https://www.google.com` | 200: 7 findings (3 cookie findings), TLSv1.3 |
| Real site | `https://www.mozilla.org/en-US/` | 200: 2 findings, TLSv1.3 |
| Real site | `https://www.wikipedia.org` | 200: 5 findings, TLSv1.3 |
| Real site | `https://www.cloudflare.com` | 200: 6 findings, TLSv1.3 |
| Redirect | `http://github.com` | 200: `HTTP_REDIRECTS_TO_HTTPS` + header findings for the redirect response |
| Redirect | `https://google.com` | 200: findings describe the redirect response (redirects are not followed) |
| Bad certificate | `https://wrong.host.badssl.com` | 200: one `CERT_VERIFICATION_FAILED` (HIGH) finding |
| Unreachable | `https://nonexistent-host-xyz123.invalid` | 400: "Could not resolve hostname" |
| Unreachable | `https://example.com:8443` | 400: "The request timed out." in 5.6 s |
| Internal | `localhost`, `127.0.0.1`, `[::1]`, `0.0.0.0`, `10.0.0.1`, `192.168.1.1`, `169.254.169.254` | 400: "Target resolved to a non-public IP" (all 7) |
| Bad port | `:22`, `:99999` | 400: port not allowed / out of range |
| Malformed | `ftp://`, `https://`, empty, `user:pass@`, 3000-character URL | 400 with a specific message (all 5) |
| Missing parameter | `/scan` with no `url` | 422 (FastAPI validation) |

**Limits (default settings)**

| Check | Result |
|---|---|
| 5 slow scans sent at once (limit 3) | 3 processed; 2 refused instantly with 503 |
| 12 requests in one minute (limit 10) | Requests 11 and 12 refused with 429 |
| `/health` while rate-limited | 200 (not rate-limited) |

**Environmental notes, not bugs.** During this run `expired.badssl.com`,
`self-signed.badssl.com` and `untrusted-root.badssl.com` reset the connection
before sending a certificate, and `http://neverssl.com` was unreachable. The
same happened with plain `curl`, so the cause was outside this project. Earlier
the same day these hosts did respond, and the raised errors were the same
certificate-error type handled by `CertificateVerificationError` (covered by
unit tests).

## 4. Frontend-to-backend checks (2026-10-19)

Checked in a browser against the running backend:

- **Report matches the API exactly.** For `https://www.google.com`, the
  dashboard was compared field by field with the exact JSON response it
  received. All 7 findings (ID, severity, title, evidence, remediation), all 5
  severity counts and all 6 TLS fields matched, and each section was sorted by
  severity.
- **Plain HTTP** (`http://github.com`): 6 findings in the correct sections;
  the TLS area states that there was no encrypted connection.
- **Certificate failure**: one HIGH finding; headers and cookies are shown
  as "Not checked", not "no issues".
- **Input validation**: empty input, `ftp://`, `localhost` and URLs with
  credentials each show a specific message, and `www.google.com` without a
  scheme is accepted as HTTPS.
- **Layout**: desktop width, and 375 px phone width with no horizontal scroll.
- **Accessibility**: severity colours and text pass WCAG AA contrast (at least
  4.5:1), the URL field is labelled, and the button has a visible keyboard focus.
- **Console**: no errors on a fresh page load.

## 5. Bugs found by integration testing

| Problem found | Fix |
|---|---|
| A host with several unreachable IPs took the 5 s connect timeout once per IP (10.7 s for `example.com:8443`). | One shared time budget for DNS and all connection attempts (5.6 s). Regression test: `test_connect_timeout_is_shared_across_all_resolved_ips`. |
| Two unit tests made real network connections and would fail offline. | Patched the correct names, and replaced the real connection with a recorder. |

## 6. Live deployment results (2026-10-20)

Run against the Vercel deployment (dashboard
https://sentinel-zero-ten.vercel.app, API https://sentinel-zero-api.vercel.app):

| Check | Result |
|---|---|
| `/health` | 200 `{"status":"healthy"}` |
| Scan `https://example.com` via the API | 5 findings, TLSv1.3, certificate details, same as locally |
| Scan `https://github.com` from the live dashboard | 2 findings with TLS details; status "System Operational"; **0 CSP violations** |
| `http://169.254.169.254/latest/meta-data/` (cloud metadata) | 400, "non-public IP" |
| `http://127.0.0.1:9001/...` (Vercel's internal runtime API) | 400, port not allowed |
| `http://localhost/`, `http://10.0.0.1/`, `http://[::1]/` | 400, "non-public IP" |
| `https://example.com:22` | 400, port not allowed |
| Dashboard origin allowed by CORS | `access-control-allow-origin: https://sentinel-zero-ten.vercel.app` |
| Sentinel Zero scanning its own dashboard | **No findings**, TLSv1.3 |
| Sentinel Zero scanning its own API | **No findings**, TLSv1.3 |
| 14 quick requests, before the firewall rule | 10 processed, then 429 from the app's own limiter (visitor IP from `x-real-ip`) |
| 14 quick requests, after the firewall rule | 10 processed, then 429 from **Vercel's firewall** (`x-vercel-mitigated: deny`), before reaching the app |

## 7. Known gaps

- There are no automated frontend tests (e.g. Vitest or Playwright). The
  frontend checks above were done in a browser by hand.
- Redirects are not followed, so findings for a redirecting URL describe the
  redirect response. The report says so, but scanning the final URL gives the
  more meaningful result.
- The "connected IP" is the address the backend connected to from this
  network; a site behind a CDN may show a different IP elsewhere.
