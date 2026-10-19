# Sentinel Zero — Presentation and Viva Guide

A study guide for presenting and defending the project. Everything here
describes what the code actually does; file names point to where you can show
it.

---

## 1. The project in two minutes

> Sentinel Zero is a **passive website security analyzer**. You enter a website
> address, and it makes one normal HTTPS request, like a browser would. It then
> checks three things: the **TLS certificate and connection**, the **HTTP
> security headers**, and the **security attributes of cookies**. It produces a
> report where every finding has a severity, the exact evidence observed, an
> explanation and a fix.
>
> The hard part was making the scanner **itself** safe. A server that fetches
> any URL a user types can be tricked into reaching internal systems: this is
> **SSRF**. I protect against it at the moment each connection is made, which
> also stops a trick called **DNS rebinding**. The backend is FastAPI in Python,
> the dashboard is React and TypeScript, and there are 135 automated tests.

## 2. Suggested presentation outline (10–12 slides)

1. **Title:** Sentinel Zero, a passive website security analyzer.
2. **Problem:** websites often miss simple protections; checking by hand is
   slow; a scanner can itself be abused (SSRF).
3. **Objectives:** the six objectives in the README.
4. **What it checks:** TLS, headers, cookies, with one example finding each.
5. **Architecture:** the diagram from the README.
6. **Request flow:** the 7 steps from URL to report.
7. **Security design 1:** SSRF and DNS rebinding, and the connection-time fix.
8. **Security design 2:** the other defences table (redirects, ports, body,
   limits).
9. **Severity model:** the levels, and why `critical` is never used.
10. **Demo:** live scan (see section 9).
11. **Testing:** 135 offline tests, 7 live tests, bugs found by testing.
12. **Limitations and future work.**

## 3. Key concepts in simple words

**HTTP response headers.** Extra lines a server sends with every page, e.g.
`Strict-Transport-Security: max-age=31536000`. Some of them tell the browser
to switch on protections.

**HTTPS / TLS.** TLS encrypts the connection. The server proves its identity
with a **certificate** signed by a trusted authority. A certificate can fail
verification if it has expired, is self-signed, or was issued for a different
hostname.

**HSTS (Strict-Transport-Security).** Tells the browser "only ever use HTTPS
for this site, for `max-age` seconds". Without it, an attacker on public Wi-Fi
can intercept the first plain-HTTP request and keep the victim on HTTP
(**SSL stripping**). `max-age=0` switches HSTS *off*.

**CSP (Content-Security-Policy).** A list of where scripts and other resources
may load from. It limits the damage of **XSS** (an attacker injecting script
into a page). `'unsafe-inline'` and `'unsafe-eval'` weaken it a lot.

**X-Frame-Options / CSP `frame-ancestors`.** Stop other sites from embedding
the page in an invisible frame and tricking users into clicking
(**clickjacking**).

**X-Content-Type-Options: nosniff.** Stops the browser from guessing a file's
type, which could turn an uploaded "image" into executable script.

**Referrer-Policy.** Controls how much of the current URL is sent to other
sites. `unsafe-url` leaks full URLs, including any tokens in them.

**Cookie attributes.**
- `Secure`: only sent over HTTPS.
- `HttpOnly`: JavaScript cannot read the cookie, so XSS cannot steal it.
- `SameSite`: limits cookies on cross-site requests, which helps against **CSRF**.
- `__Host-` / `__Secure-` prefixes: browsers enforce extra rules for these names.

**Passive vs active scanning.** Passive means only observing normal responses.
Active means sending attack payloads, guessing passwords and so on. Sentinel
Zero is strictly passive.

**SSRF (Server-Side Request Forgery).** Tricking a server into making requests
on the attacker's behalf, e.g. to `http://169.254.169.254/`, the cloud
metadata service that can hand out server credentials, or to `localhost`
admin pages.

**DNS rebinding.** The attacker controls a domain's DNS. When the scanner
checks it, DNS answers with a public IP. A moment later, when the scanner
connects, DNS answers `127.0.0.1`. The check and the use see different
answers: a **time-of-check to time-of-use (TOCTOU)** bug.

**Gzip bomb.** A small compressed download that expands to a huge size in
memory.

**CORS.** Browser rules about which websites may call an API from JavaScript.

## 4. Component responsibilities

| File | Responsibility |
|---|---|
| `app/main.py` | API endpoints, rate limit, concurrency limit, overall timeout, mapping errors to HTTP status codes, building the report |
| `core/validator.py` | Early checks: scheme, credentials, port allow-list, DNS, "is every IP public?" (`is_public_ip`, `check_resolved_ips`) |
| `core/safe_transport.py` | **The SSRF guard.** `PublicOnlyBackend.connect_tcp` resolves, checks and connects to the checked IP for every connection |
| `core/http_client.py` | `SecureHTTPClient`: one GET request, no redirects, no body, collects TLS details and the connected IP, turns certificate failures into `CertificateVerificationError` |
| `analyzers/ssl_check.py` | HTTP vs HTTPS, redirects to HTTPS, certificate expiry, failed verification |
| `analyzers/header_check.py` | Missing / empty / weak security headers |
| `analyzers/cookie_check.py` | Parses each `Set-Cookie` and checks its attributes, hiding values |
| `schemas/report.py` | Pydantic models: `Severity`, `Finding`, `AnalysisReport` |
| `frontend/src/...` | Dashboard: input checks, API calls, grouping and sorting findings, display |

## 5. Code walkthrough: the parts examiners are likely to ask about

### 5.1 The connection-time SSRF guard (`core/safe_transport.py`)

httpx sends every TCP connection through an httpcore "network backend". I
replaced the default backend with `PublicOnlyBackend`. Its `connect_tcp`:

1. checks the port is allowed;
2. resolves the hostname **once** (`anyio.getaddrinfo`);
3. calls `check_resolved_ips`, which raises an error if **any** address is
   non-public;
4. connects to one of those **already-checked IP addresses**, not the
   hostname, so there is no second DNS lookup an attacker could change;
5. shares one time budget across DNS and all attempts.

TLS still works because httpcore uses the original **hostname** for SNI and
certificate verification, even though the socket connects to an IP.

*Why not just call `validate_target()` twice?* Because the attacker can simply
answer correctly twice and switch on the third lookup. The only safe approach
is to validate the exact address you connect to.

### 5.2 Deciding whether an IP is public (`core/validator.py`)

`is_public_ip` starts from Python's `ipaddress`, but does not trust
`is_global` alone. On this Python version `224.0.0.1` (multicast) and
`64:ff9b::7f00:1` (NAT64 wrapping 127.0.0.1) both count as "global". The
function therefore:
- judges IPv6 addresses that wrap an IPv4 address (IPv4-mapped, NAT64) by the
  IPv4 address inside;
- rejects the deprecated IPv4-compatible forms outright;
- explicitly rejects multicast, unspecified, reserved, loopback, link-local
  and private addresses.

### 5.3 Using the verified connection for TLS details (`core/http_client.py`)

While the response stream is still open, the client reads the `ssl_object`
of the connection httpx already verified, and records the protocol version,
cipher and certificate. An earlier version opened a **second** raw socket for
this, which skipped the SSRF checks; this design avoids that.

### 5.4 Missing vs empty vs weak (`analyzers/header_check.py`)

Each header can be absent (`MISSING_CSP`), present but empty (`CSP_EMPTY`), or
present but weak (`CSP_UNSAFE_EVAL`, `HSTS_WEAK`...). Repeated headers are read
one by one with `get_list`, because httpx would otherwise join them with
commas and break parsing.

### 5.5 Cookies without leaking secrets (`analyzers/cookie_check.py`)

`parse_set_cookie` splits the cookie into its name and attribute names. The
value is never stored in a finding. Severity depends on whether the *name*
looks like a session cookie (`sess`, `token`, `auth`...). This is a documented
guess, and the finding text says so.

## 6. Design decisions and trade-offs

| Decision | Why | Trade-off |
|---|---|---|
| Passive only | Safe and legal to run; no harm to the target | Cannot prove a vulnerability exists |
| Validate at connection time | The only reliable defence against DNS rebinding | Replaces a private httpx attribute (`_pool`); versions are pinned and tests catch breakage |
| Don't follow redirects | Every hop could point somewhere internal | Findings describe the redirect response, not the final page |
| Don't download the body | No analyzer needs it; removes gzip-bomb and corrupt-body risks | Content checks (e.g. mixed content) would need careful body reading |
| Port allow-list (80/443/8080/8443) | Stops use as a port scanner | Sites on unusual ports cannot be scanned |
| Name-based cookie severity | A passive scan cannot know a cookie's purpose | It is a heuristic and can be wrong |
| No `critical` severity | Passive evidence cannot confirm exploitability | Highest real level is `high` |
| No overall "security score" | A single score would overstate what a passive scan knows | Less "at a glance" summary |
| Certificate failure = finding, not error | A bad certificate *is* the most important TLS result | Headers and cookies are marked "not checked" |
| In-memory rate limiter | Simple and enough for a single server | Needs Redis for multiple servers |

## 7. Testing strategy

- **Unit tests** for every analyzer, the validator and the HTTP client
  (mocked responses, edge cases).
- **Security tests** that run a real HTTP server on `127.0.0.1` as the
  "internal service" and prove no request ever reaches it: rebinding, proxy
  variables, 24 special IP addresses, unusual notations such as
  `http://2130706433/`.
- **API tests** for limits, CORS, error messages and logging without leaks.
- **Documentation test:** `docs/SEVERITY.md` must match the code.
- **Regression discipline:** every security test was confirmed to *fail* on
  the old code before the fix.
- **Offline by default:** a network audit removed hidden internet use from the
  test suite; live tests are opt-in (`-m live`).
- **Integration:** a live matrix of 29 cases and browser checks, recorded in
  [TESTING.md](TESTING.md).

## 8. The development story: real bugs found and fixed

These are good to mention, because they show testing and debugging, not just
writing code.

1. **Every scan failed** with "An unexpected error occurred". The cause was
   that httpx had already decompressed the gzip body, the code put back the
   `Content-Encoding: gzip` header, and httpx then tried to decompress plain
   text a second time. The generic error handler hid this. Fixed, and a
   regression test added.
2. **SSRF through DNS rebinding.** A test with a fake DNS server and a real
   loopback service proved the old client fetched "internal" data. Fixed with
   the connection-time guard.
3. **The TLS analyzer bypassed the SSRF checks** by opening its own socket. It
   also froze the server while connecting, and its "expired certificate" check
   could never run. Fixed by reading TLS details from the verified connection.
4. **Cookie values were copied into reports**, possibly leaking session
   tokens. Fixed by hiding the values.
5. **Gzip bomb:** a 190 KB response made one scan use about 150 MB of memory.
   Fixed by not downloading the body.
6. **A timeout multiplied per IP address** (10.7 s instead of 5 s), found by
   the live test matrix. Fixed with a shared time budget.

## 9. Demo script

**Before the viva:** start the backend and frontend (see README), and open
http://localhost:5173. Check that the badge says "System Operational".

1. Scan `https://github.com`: a mostly good site. Point out the TLS details,
   the one CSP weakness with its evidence, and the cookie finding with its
   value hidden.
2. Scan `https://www.google.com`: findings in all sections, sorted by
   severity.
3. Scan `https://wrong.host.badssl.com`: a certificate failure. Point out that
   headers and cookies say "Not checked", not "no issues".
4. Scan `http://github.com`: HTTP redirecting to HTTPS (LOW, not HIGH).
5. Try `http://169.254.169.254/` and `localhost`: refused, which shows the SSRF
   protection.
6. Optionally run `python -m pytest -v` to show the tests.

**If the internet fails during the viva:** steps 5 and 6 still work offline
(blocked targets and the full test suite). Have the screenshots in
`docs/screenshots/` ready as a backup.

## 10. Likely viva questions, with answers

**Q: What is the difference between your tool and a vulnerability scanner like Nessus or OWASP ZAP?**
Those can actively test for vulnerabilities by sending attack payloads. Mine
is passive: it only inspects one normal response for missing or weak security
configuration. It is safer to run, but it cannot prove a vulnerability exists.

**Q: What is SSRF, and why is it relevant to *your* project?**
SSRF is when an attacker makes a server send requests for them. My server
fetches any URL a user enters, so without protection someone could point it
at `localhost` or `169.254.169.254` and read internal data through my tool.

**Q: Explain DNS rebinding and how you stopped it.**
DNS can answer differently each time. An attacker answers "public IP" when I
check and "127.0.0.1" when I connect. I stopped it by doing the check inside
the connection step and connecting to the exact IP I checked, so there is no
gap between the check and the use.

**Q: Why not just resolve the IP and request `https://<ip>/`?**
TLS certificate verification and SNI need the hostname. Connecting by IP
while keeping the hostname for TLS is exactly what my custom network backend
does.

**Q: Why don't you follow redirects?**
A redirect can point to an internal address. Following them safely would
need the same SSRF checks on every hop. Not following them is simpler and
safe. The limitation is documented, and it is listed as future work.

**Q: How do you decide severity?**
From a documented table in `docs/SEVERITY.md`, e.g. a missing core defence
against a common attack is medium, a weakened defence is low. A test checks
that the document and the code agree. I never use `critical`, because a passive
scan cannot confirm that something is exploitable.

**Q: Why is a missing CSP medium and not high?**
CSP limits the damage of XSS, but it is a second line of defence. A site
without CSP is not automatically exploitable. That depends on whether an XSS
bug exists, which a passive scan cannot know.

**Q: Why do cookies get different severities?**
A missing `HttpOnly` matters a lot for a session cookie, which XSS could steal
to hijack the session, and very little for a theme cookie that scripts are
meant to read. I can only guess the purpose from the name, so the report says
it is a guess.

**Q: Why don't you show the cookie values?**
They may be session tokens or other secrets. A security tool should not copy
secrets into reports, screenshots or logs.

**Q: Why do you report "connected IP" instead of just resolving the domain?**
That is the address the scanner really connected to, after validation.
Resolving again for the report could give a different answer.

**Q: What happens if a site's certificate is expired?**
The connection is refused (verification is never turned off). That failure is
reported as a HIGH `CERT_VERIFICATION_FAILED` finding with OpenSSL's reason,
and header and cookie checks are marked "not checked".

**Q: Can your tool be used to attack sites?**
It sends one normal GET request, which is the same as visiting the home page.
It is also rate limited (10 scans per minute per IP) and limited to web ports.
It still includes an authorization notice, because scanning without permission
may break terms of service.

**Q: How do you stop people overloading your server?**
A per-IP rate limit, a limit of 3 concurrent scans (extras are refused
instantly with 503), timeouts at several levels, and the body is never
downloaded.

**Q: What is the weakest part of your design?**
It replaces a private attribute of httpx to install the custom backend. I
pinned the httpx version and wrote tests that fail if a future version breaks
it. In production I would also add network-level egress rules as a second
layer.

**Q: How did you test that SSRF protection actually works?**
I run a real HTTP server on `127.0.0.1` in the tests and simulate rebinding
DNS. The tests assert that the server receives zero requests. I also
confirmed the tests fail on the old code.

**Q: Why FastAPI?**
It is async, which suits network-bound work like scanning, and it validates
input and output with Pydantic. It also generates API docs at `/docs`.

**Q: Why is DNS resolution run in a thread?**
`socket.getaddrinfo` blocks. In an async server, a slow DNS lookup would
freeze every user's request, so it runs in a worker thread with
`asyncio.to_thread`.

**Q: What would you add next?**
Safe redirect following, more headers (`Permissions-Policy`, COOP), report
export, automated frontend tests, and deployment with a shared rate limiter.

## 11. Honest limitations to state confidently

- A clean report does **not** mean the site is secure.
- Only one response is analysed; redirects are not followed.
- Only the negotiated TLS version is visible.
- Cookie sensitivity is a name-based guess.
- The project is not yet deployed publicly.
