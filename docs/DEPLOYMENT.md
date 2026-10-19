# Sentinel Zero — Deploying to Vercel

**Status: prepared, not yet deployed.** This guide explains how to deploy
Sentinel Zero on Vercel's free Hobby plan and how to check that its security
protections still work once it is online.

## 1. Why Vercel, and what to know first

Checked against Vercel's official documentation in October 2026:

| Requirement | Vercel Hobby (free) |
|---|---|
| Cost | Free, no credit card needed |
| FastAPI backend | Supported; detects `app/main.py` with a FastAPI `app` automatically |
| Python version | 3.12 (default), 3.13, 3.14; this project pins 3.14 in `backend/.python-version` |
| Outbound internet (to scan sites) | Allowed |
| Function time limit | 300 s maximum; this project sets 30 s (scans stop at 15 s) |
| Visitor IP | `x-real-ip` header, set by Vercel; client-supplied values are overwritten, so it cannot be faked |
| Rate limiting | WAF rate limiting is available on Hobby: 1 rule per project, counted per IP |
| Frontend security headers | Set in `backend/frontend/vercel.json` |

**Things that are different from running locally**
- **Serverless:** the backend runs as a Vercel Function that can start several
  copies. The built-in in-memory rate limit and the 3-scan concurrency limit
  apply **per copy**, so the **Vercel WAF rate-limit rule (step 5) is the real
  limit**. The in-memory one is a second layer.
- **Hobby plan terms:** personal, non-commercial use only. That fits a student
  project.
- **Logs:** runtime logs are kept for 1 hour on Hobby.
- **Region:** functions run in Washington, D.C. (`iad1`) by default, so the
  "connected IP" in reports is what the US region resolved.

## 2. What is already prepared in the code

| File | Purpose |
|---|---|
| `backend/vercel.json` | Function settings: 30 s limit; leaves tests and the frontend out of the backend bundle |
| `backend/.python-version` | Python 3.14 |
| `backend/requirements.txt` | Runtime packages only; `pytest` moved to `requirements-dev.txt` |
| `backend/app/main.py` | `TRUSTED_CLIENT_IP_HEADER` setting for the real visitor IP; security headers on every API response |
| `backend/frontend/vercel.json` | Strict security headers for the dashboard (CSP, HSTS, X-Frame-Options, and more) |

Both were verified locally: the production frontend build runs under the
strict CSP with **zero violations**, and Sentinel Zero's own header analyzer
reports **no issues** for either the frontend or the API.

## 3. Deploy the backend

1. Push the latest code to GitHub (`main` branch).
2. Sign in at https://vercel.com with your GitHub account and choose the
   **Hobby** plan.
3. **Add New → Project**, import `Lakshay-Khatri/sentinel-zero`.
4. Set **Root Directory** to `backend`. Vercel should detect **FastAPI**.
5. Under **Environment Variables**, add:

   | Name | Value |
   |---|---|
   | `TRUSTED_CLIENT_IP_HEADER` | `x-real-ip` |
   | `RATE_LIMIT_MAX_REQUESTS` | `10` |
   | `MAX_CONCURRENT_SCANS` | `3` |

   (`ALLOWED_ORIGINS` is added in step 4, once the frontend URL is known.)
6. Click **Deploy**, and note the URL, e.g. `https://sentinel-zero-api.vercel.app`.
7. Open `https://<backend-url>/health`. **Expected:** `{"status":"healthy"}`.

> Only set `TRUSTED_CLIENT_IP_HEADER` on a platform that overwrites that
> header itself, as Vercel does with `x-real-ip`. Locally it must stay unset.

## 4. Deploy the frontend

1. **Add New → Project**, import the **same** repository again.
2. Set **Root Directory** to `backend/frontend`. Vercel should detect **Vite**.
3. Add the environment variable `VITE_API_BASE_URL` = `https://<backend-url>`
   (no trailing slash).
4. Click **Deploy** and note the frontend URL.
5. Back in the **backend** project → Settings → Environment Variables, add
   `ALLOWED_ORIGINS` = `https://<frontend-url>`. Then **Redeploy** the backend
   so the setting takes effect.
6. **Tighten the CSP:** in `backend/frontend/vercel.json`, replace
   `https://*.vercel.app` in `connect-src` with the exact backend URL. Commit
   and push; Vercel redeploys automatically. The wildcard is only there so the
   first deploy works before the backend URL is known.

## 5. Add the rate-limit rule (backend project)

Backend project → **Firewall** → **Configure** → **New Rule**:
- **If:** Request Path *starts with* `/scan`
- **Then:** Rate Limit, *Fixed Window*, **60 s**, **10** requests, key **IP**,
  action **Default (429)**
- **Save**, then **Review Changes → Publish**.

## 6. Verify the deployment

Run these from PowerShell, replacing `<api>` with the backend URL.

| Check | Command or action | Expected |
|---|---|---|
| Health | `Invoke-RestMethod https://<api>/health` | `status: healthy` |
| Real scan | Scan `https://example.com` in the dashboard | A report with findings and TLS details (counts may differ slightly from local results, since the scan runs from the US) |
| Cloud metadata blocked | `Invoke-RestMethod "https://<api>/scan?url=http://169.254.169.254/"` | 400, "non-public IP" |
| Function runtime API blocked | `Invoke-RestMethod "https://<api>/scan?url=http://127.0.0.1:9001/"` | 400 (port not allowed) |
| Private range blocked | `Invoke-RestMethod "https://<api>/scan?url=http://10.0.0.1/"` | 400, "non-public IP" |
| Rate limit | Scan 11 times within a minute | The 11th returns 429 |
| Own frontend | Scan `https://<frontend-url>` in the dashboard | No header findings |
| Own API | Scan `https://<api>/health` | No header findings |

Record the results in `docs/TESTING.md`, like the local integration run.

## 7. Updating later

Every push to `main` redeploys both projects automatically. Pushes to other
branches create *preview* deployments, which Vercel protects with a login by
default.
