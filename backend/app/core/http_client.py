import asyncio
import logging
import httpx
import ssl
from typing import Optional
from app.core.validator import validate_target, SecurityValidationError
from app.core.safe_transport import build_public_only_transport

logger = logging.getLogger(__name__)

# Headers describing how the body was encoded on the wire. The body is not
# kept, so they no longer apply and are removed on reconstruction.
_TRANSPORT_HEADERS = {"content-encoding", "content-length", "transfer-encoding"}


def _strip_transport_headers(headers) -> httpx.Headers:
    """Copy headers (keeping duplicates such as Set-Cookie) minus transport headers."""
    return httpx.Headers(
        [(k, v) for k, v in httpx.Headers(headers).multi_items() if k.lower() not in _TRANSPORT_HEADERS]
    )


class CertificateVerificationError(Exception):
    """The server's TLS certificate failed verification (expired, self-signed, wrong host...)."""
    def __init__(self, verify_message: str):
        super().__init__(verify_message)
        # OpenSSL's short reason, e.g. "certificate has expired". Safe to show users.
        self.verify_message = verify_message


def _find_cert_verification_error(exc: BaseException) -> Optional[ssl.SSLCertVerificationError]:
    """Walk the exception chain (httpx -> httpcore -> ssl) looking for a certificate error."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        if isinstance(exc, ssl.SSLCertVerificationError):
            return exc
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
    return None


def _read_tls_info(response: httpx.Response) -> Optional[dict]:
    """
    Read TLS details from the connection httpx already made and verified.
    Using the same connection avoids a second, unvalidated connection to the target.
    """
    network_stream = response.extensions.get("network_stream")
    if network_stream is None:
        return None
    ssl_object = network_stream.get_extra_info("ssl_object")
    if not isinstance(ssl_object, (ssl.SSLObject, ssl.SSLSocket)):
        return None  # plain HTTP
    cipher = ssl_object.cipher()
    return {
        "version": ssl_object.version(),
        "cipher": cipher[0] if cipher else None,
        "certificate": ssl_object.getpeercert(),
    }

def _read_connected_ip(response: httpx.Response) -> Optional[str]:
    """The IP address the socket is actually connected to."""
    network_stream = response.extensions.get("network_stream")
    if network_stream is None:
        return None
    server_addr = network_stream.get_extra_info("server_addr")
    if isinstance(server_addr, tuple) and server_addr and isinstance(server_addr[0], str):
        return server_addr[0]
    return None


class SecureHTTPClient:
    """
    A hardened HTTP client for passive security scanning.

    Every outbound TCP connection goes through PublicOnlyBackend
    (app.core.safe_transport), which resolves the hostname once, rejects
    non-public addresses and connects to the checked IP. This closes the
    DNS-rebinding gap between validation and connection. Redirects are not
    followed and proxy environment variables are ignored.

    The response body is never downloaded: the analyzers only need the status
    line, headers and TLS details. Skipping the body removes the risk of huge
    or maliciously compressed bodies ("gzip bombs"). A future analyzer that
    needs page content must add a size limit that counts *raw* (compressed)
    bytes, not decoded bytes.

    Defence in depth: when deployed publicly, also restrict outbound traffic
    at the network level (firewall / egress rules) where the host allows it.
    """
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """
        Performs a secure passive request.
        """
        # 1. Early validation for clear error messages (scheme, port, DNS).
        # The binding enforcement happens again at connection time (step 3).
        # Blocking DNS runs in a worker thread so it cannot stall the event loop.
        await asyncio.to_thread(validate_target, url)

        # 2. Request Configuration
        # Force no redirects to prevent SSRF and unauthorized target hopping.
        kwargs["follow_redirects"] = False

        try:
            # 3. TLS verification stays enabled inside the transport.
            # trust_env=False: ignore HTTP(S)_PROXY and similar environment settings,
            # which could otherwise route scans through another host.
            async with httpx.AsyncClient(
                transport=build_public_only_transport(),
                timeout=self.timeout,
                trust_env=False,
            ) as client:
                # stream() returns as soon as the headers arrive. Leaving the
                # block without reading closes the connection, so the body is
                # never downloaded or decompressed.
                async with client.stream(method, url, **kwargs) as response:
                    # We build a header-only response for the analyzers.
                    # The transport headers describe a body we did not keep, so they
                    # are dropped; httpx would otherwise try to decode an empty body as
                    # gzip etc. Every other header (security headers, repeated
                    # Set-Cookie) is kept.
                    return httpx.Response(
                        status_code=response.status_code,
                        headers=_strip_transport_headers(response.headers),
                        content=b"",
                        request=response.request,
                        # TLS details for the TLS analyzer (None for plain HTTP),
                        # and the IP address that was really connected to.
                        extensions={
                            "tls_info": _read_tls_info(response),
                            "connected_ip": _read_connected_ip(response),
                        },
                    )

        except httpx.TimeoutException:
            raise SecurityValidationError("The request timed out.")
        except (httpx.TransportError, ssl.SSLError) as e:
            # A failed certificate check is a scan *result*, not just an error.
            cert_error = _find_cert_verification_error(e)
            if cert_error is not None:
                raise CertificateVerificationError(
                    cert_error.verify_message or "certificate verification failed"
                )
            raise SecurityValidationError("A network or TLS error occurred.")
        except httpx.InvalidURL:
            raise SecurityValidationError("Malformed URL.")
        except httpx.HTTPError:
            raise SecurityValidationError("The target sent a response that could not be processed.")
        except SecurityValidationError:
            raise
        except Exception:
            # Unknown failure: log the full traceback server-side (never sent to the
            # client) so bugs are diagnosable instead of hidden, as the original
            # gzip bug was. The URL is deliberately not logged.
            logger.exception("Unexpected error during scan request")
            raise SecurityValidationError("An unexpected error occurred during the scan.")
