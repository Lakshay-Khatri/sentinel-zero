import httpx
import ssl
from typing import Optional
from app.core.validator import validate_target, SecurityValidationError

# Headers describing how the body was encoded on the wire. They no longer
# match once httpx has decoded the body, so they are removed on reconstruction.
_TRANSPORT_HEADERS = {"content-encoding", "content-length", "transfer-encoding"}


def _strip_transport_headers(headers) -> httpx.Headers:
    """Copy headers (keeping duplicates such as Set-Cookie) minus transport headers."""
    return httpx.Headers(
        [(k, v) for k, v in httpx.Headers(headers).multi_items() if k.lower() not in _TRANSPORT_HEADERS]
    )

class SecureHTTPClient:
    """
    A hardened HTTP client for passive security scanning.

    SECURITY WARNING: This client uses hostname-based requests after validation.
    It does NOT prevent DNS-rebinding attacks. For production-grade protection,
    an egress proxy or network-level IP pinning is required.
    """
    def __init__(self, timeout: float = 5.0, max_body_size: int = 1024 * 1024):
        self.timeout = timeout
        self.max_body_size = max_body_size

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """
        Performs a secure passive request.
        """
        # 1. Mandatory Backend Validation
        # Ensures the target currently resolves to a public IP.
        validate_target(url)

        # 2. Request Configuration
        # Force no redirects to prevent SSRF and unauthorized target hopping.
        kwargs["follow_redirects"] = False

        # TLS verification is ENABLED by default in httpx.
        # AsyncClient.stream() does not accept 'verify' as a keyword argument;
        # verification is configured on the client instance itself.

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=True) as client:
                # We use a stream to enforce body size limits strictly.
                async with client.stream(method, url, **kwargs) as response:
                    # We read the headers first.
                    content_length = response.headers.get("Content-Length")
                    if content_length and int(content_length) > self.max_body_size:
                        raise SecurityValidationError("Response body too large (Content-Length).")

                    # Read the body in chunks to enforce the size limit.
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > self.max_body_size:
                            raise SecurityValidationError("Response body too large (streamed).")

                    # We reconstruct a response object for the analyzers to use.
                    # aiter_bytes() has already decompressed the body, so we must drop
                    # the transport headers that describe the *original* encoded body.
                    # Otherwise httpx tries to gunzip plain bytes again (DecodingError).
                    # Every other header (security headers, repeated Set-Cookie) is kept.
                    return httpx.Response(
                        status_code=response.status_code,
                        headers=_strip_transport_headers(response.headers),
                        content=bytes(body),
                        request=response.request
                    )

        except httpx.TimeoutException:
            raise SecurityValidationError("The request timed out.")
        except (httpx.TransportError, ssl.SSLError):
            raise SecurityValidationError("A network or TLS error occurred.")
        except Exception as e:
            if isinstance(e, SecurityValidationError):
                raise e
            # Sanitize internal error messages.
            raise SecurityValidationError("An unexpected error occurred during the scan.")
