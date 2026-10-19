from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
import os
import asyncio
from app.core.validator import validate_target, SecurityValidationError
from app.core.http_client import SecureHTTPClient, CertificateVerificationError
from app.analyzers.ssl_check import analyze_ssl, certificate_failure_finding, tls_metadata
from app.analyzers.header_check import analyze_headers
from app.analyzers.cookie_check import analyze_cookies
from app.schemas.report import AnalysisReport, Finding
from typing import Dict
import time

app = FastAPI(title="Sentinel Zero API")

# Configuration
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
SCAN_TIMEOUT = float(os.getenv("SCAN_TIMEOUT", "15.0"))

# Simple In-Memory Rate Limiter (Per-Process)
# In a production environment, this would be replaced by Redis
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "10"))
request_history: Dict[str, list] = {}

# Semaphore for concurrency control
scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

secure_client = SecureHTTPClient()

async def rate_limiter(request: Request):
    """
    Basic in-memory rate limiter.
    Note: This only works within a single worker process.
    """
    # Derive client IP safely from the ASGI request.
    # request.client.host is the immediate peer's IP.
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()

    if client_ip not in request_history:
        request_history[client_ip] = []

    # Remove requests older than the window
    request_history[client_ip] = [t for t in request_history[client_ip] if now - t < RATE_LIMIT_WINDOW]

    if len(request_history[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Please try again in a few moments. (Limit: {RATE_LIMIT_MAX_REQUESTS} requests per minute)"
        )

    request_history[client_ip].append(now)

@app.get("/scan")
async def run_scan(url: str, _ = Depends(rate_limiter)):
    """
    Performs a passive security scan of the provided URL.
    """
    # Fail-fast concurrency limit: reject immediately if no slots are available.
    if scan_semaphore.locked():
        raise HTTPException(
            status_code=503,
            detail="The security backend is currently at full capacity. Please try again in a few moments."
        )

    async with scan_semaphore:
        try:
            # Overall scan timeout to prevent hanging tasks
            return await asyncio.wait_for(
                _execute_scan(url),
                timeout=SCAN_TIMEOUT
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=504,
                detail="The security scan timed out. The target may be unresponsive or too slow."
            )

async def _execute_scan(url: str):
    """Internal logic for executing the scan."""
    try:
        # 1. Validate Target
        _, validated_ip = validate_target(url)

        # 2. Execute Request
        try:
            response = await secure_client.request("GET", url)
        except CertificateVerificationError as e:
            # No trusted connection was made, so only the certificate result is reported.
            return AnalysisReport(
                target_url=url,
                validated_ip=validated_ip,
                findings=[certificate_failure_finding(e.verify_message)],
                scan_metadata={
                    "status": "completed",
                    "note": "Header and cookie checks were skipped because the certificate could not be verified.",
                }
            )

        # 3. Run Analyzers
        ssl_findings = analyze_ssl(url, response)
        header_findings = analyze_headers(response)
        cookie_findings = analyze_cookies(response)

        # 4. Aggregate Results
        all_findings = ssl_findings + header_findings + cookie_findings

        return AnalysisReport(
            target_url=url,
            # Prefer the address actually connected to (validated at connection time).
            validated_ip=response.extensions.get("connected_ip") or validated_ip,
            findings=all_findings,
            scan_metadata={"status": "completed", **tls_metadata(response)}
        )

    except SecurityValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="An internal server error occurred.")

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
