"""
Connection-time SSRF protection for outbound scan requests.

Why this exists
---------------
validate_target() checks a hostname *before* the request. But httpx would then
resolve the hostname again when it connects, and a malicious DNS server can
answer differently the second time (DNS rebinding), e.g. 93.184.216.34 first
and 127.0.0.1 second. Checking twice does not help, since the attacker can
just answer correctly twice and switch on the third lookup.

How it works
------------
httpx sends every TCP connection through an httpcore "network backend".
PublicOnlyBackend replaces the default one and, for every connection:
  1. checks the port against the allow-list,
  2. resolves the hostname exactly once,
  3. rejects the connection if ANY resolved address is non-public,
  4. connects to one of those already-checked IP addresses (no new lookup).

TLS is unaffected: httpcore still sends the original hostname as SNI and
verifies the certificate against it, even though the socket targets an IP.
"""
import socket
import time
from typing import Iterable, Optional

import anyio
import httpcore
import httpx

from app.core import validator
from app.core.validator import SecurityValidationError, check_resolved_ips


class PublicOnlyBackend(httpcore.AsyncNetworkBackend):
    """httpcore network backend that only connects to validated public IPs."""

    def __init__(self) -> None:
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Iterable] = None,
    ) -> httpcore.AsyncNetworkStream:
        validator.check_port_allowed(port)

        # One shared time budget for DNS plus every connection attempt, so a host
        # with several unreachable IPs cannot multiply the connect timeout.
        deadline = None if timeout is None else time.monotonic() + timeout

        def remaining() -> Optional[float]:
            return None if deadline is None else max(0.0, deadline - time.monotonic())

        try:
            with anyio.fail_after(remaining()):
                infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except TimeoutError:
            raise httpcore.ConnectTimeout("DNS resolution timed out")
        except OSError:  # includes socket.gaierror
            raise SecurityValidationError(f"Could not resolve hostname: {host}")

        ips = check_resolved_ips(host, (info[4][0] for info in infos))

        # Connect to the addresses we just validated, in resolver order.
        last_error: Exception = httpcore.ConnectTimeout("Connection timed out")
        for ip in ips:
            budget = remaining()
            if budget == 0.0:
                break
            try:
                return await self._inner.connect_tcp(
                    ip, port, timeout=budget,
                    local_address=local_address, socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as e:
                last_error = e
        raise last_error

    async def connect_unix_socket(self, *args, **kwargs) -> httpcore.AsyncNetworkStream:
        raise SecurityValidationError("Unix socket connections are not allowed.")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def build_public_only_transport() -> httpx.AsyncHTTPTransport:
    """
    An httpx transport whose connections all go through PublicOnlyBackend.

    httpx has no public option for a custom network backend, so we replace the
    transport's connection pool with an equivalent one that uses ours. The SSRF
    tests (tests/test_ssrf.py) fail if a future httpx version stops honouring this.
    """
    transport = httpx.AsyncHTTPTransport(verify=True, trust_env=False, retries=0)
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=httpx.create_ssl_context(verify=True, trust_env=False),
        network_backend=PublicOnlyBackend(),
    )
    return transport
