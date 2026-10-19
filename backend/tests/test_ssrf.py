"""
SSRF / DNS-rebinding tests for SecureHTTPClient.

These tests run a real HTTP server on 127.0.0.1 to stand in for an internal
service. A safe scanner must never deliver a request to it, no matter what
DNS says at validation time.
"""
import asyncio
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import httpcore
import pytest

from app.core.http_client import SecureHTTPClient
from app.core.safe_transport import PublicOnlyBackend
from app.core.validator import SecurityValidationError, is_public_ip, validate_url

PUBLIC_IP = "93.184.216.34"


class _InternalService:
    """A loopback HTTP server that records whether anything reached it."""

    def __init__(self):
        hits = self.hits = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "6")
                self.end_headers()
                self.wfile.write(b"secret")

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


_real_getaddrinfo = socket.getaddrinfo


def _rebinding_dns(hostname, answers):
    """
    Fake DNS for `hostname`: each lookup returns the next answer in `answers`
    (the last one repeats). Other hostnames resolve normally.
    """
    calls = {"n": 0}

    def fake(host, port, *args, **kwargs):
        if host != hostname and host != hostname.encode():
            return _real_getaddrinfo(host, port, *args, **kwargs)
        ip = answers[min(calls["n"], len(answers) - 1)]
        calls["n"] += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 0))]

    return fake, calls


def _allow_port(port):
    """The test server uses a random port; allow it for the duration of a test."""
    from app.core import validator
    return patch.object(validator, "ALLOWED_PORTS", validator.ALLOWED_PORTS | {port})


# --- DNS rebinding and connection-time enforcement --------------------------

def test_dns_rebinding_to_loopback_is_blocked():
    """DNS returns a public IP when validated, then 127.0.0.1 when connecting."""
    with _InternalService() as internal, _allow_port(internal.port):
        fake, calls = _rebinding_dns("rebind.test", [PUBLIC_IP, "127.0.0.1"])
        with patch("socket.getaddrinfo", side_effect=fake):
            with pytest.raises(SecurityValidationError):
                asyncio.run(SecureHTTPClient().request("GET", f"http://rebind.test:{internal.port}/"))

    assert internal.hits == [], "request reached the internal service"
    assert calls["n"] >= 2, "the connection step must perform its own DNS check"


def test_hostname_resolving_to_loopback_is_blocked_at_connection_time():
    """Even if the up-front validation is skipped, the connection itself is guarded."""
    with _InternalService() as internal, _allow_port(internal.port):
        fake, _ = _rebinding_dns("internal.test", ["127.0.0.1"])
        with patch("socket.getaddrinfo", side_effect=fake), \
             patch("app.core.http_client.validate_target", return_value=("http", PUBLIC_IP)):
            with pytest.raises(SecurityValidationError, match="non-public"):
                asyncio.run(SecureHTTPClient().request("GET", f"http://internal.test:{internal.port}/"))

    assert internal.hits == []


def test_proxy_environment_variables_are_ignored(monkeypatch):
    """
    An HTTP_PROXY setting must not route scans through another host.

    Two layers give this guarantee: httpx ignores proxy environment variables
    when a custom transport is passed, and the client also sets trust_env=False.
    This test failed against the original client, which used neither.
    """
    with _InternalService() as proxy, _allow_port(proxy.port):
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.port}")
        monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{proxy.port}")
        fake, _ = _rebinding_dns("public.test", [PUBLIC_IP])
        attempted = []

        async def no_real_network(self, host, port, **kwargs):
            # Record where the client tried to connect, without touching the network.
            attempted.append((host, port))
            raise httpcore.ConnectError("network disabled in tests")

        with patch("socket.getaddrinfo", side_effect=fake), \
             patch.object(httpcore.AnyIOBackend, "connect_tcp", no_real_network):
            with pytest.raises(SecurityValidationError):
                asyncio.run(SecureHTTPClient(timeout=1.0).request("GET", "http://public.test/"))

    assert proxy.hits == []
    # The client went straight to the validated target, not to the proxy.
    assert attempted == [(PUBLIC_IP, 80)]


# --- Address classification -------------------------------------------------

@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "100.64.0.1",
    "169.254.169.254",          # cloud metadata endpoint (link-local)
    "0.0.0.0", "224.0.0.1", "239.255.255.250", "255.255.255.255",
    "::1", "::", "fe80::1", "fc00::1", "fd00:ec2::254", "ff0e::1", "ff02::1",
    "::ffff:127.0.0.1", "::ffff:169.254.169.254",
    "64:ff9b::7f00:1",          # NAT64 wrapping 127.0.0.1
    "64:ff9b::a9fe:a9fe",       # NAT64 wrapping 169.254.169.254
    "::127.0.0.1",              # deprecated IPv4-compatible form
    "::ffff:0:7f00:1",          # IPv4-translated form
    "2002:7f00:1::1",           # 6to4 wrapping 127.0.0.1
    "not-an-ip", "",
])
def test_non_public_addresses_are_rejected(ip):
    assert is_public_ip(ip) is False


@pytest.mark.parametrize("ip", [
    "8.8.8.8", "93.184.216.34", "1.1.1.1",
    "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808",
])
def test_public_addresses_are_accepted(ip):
    assert is_public_ip(ip) is True


@pytest.mark.parametrize("url", [
    "http://2130706433/",       # decimal form of 127.0.0.1
    "http://0x7f.0.0.1/",       # hex form
    "http://127.1/",            # short form
    "http://0177.0.0.1/",       # octal form
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/",
])
def test_unusual_loopback_and_metadata_urls_are_blocked(url):
    with pytest.raises(SecurityValidationError):
        asyncio.run(SecureHTTPClient(timeout=1.0).request("GET", url))


# --- Port policy ------------------------------------------------------------

@pytest.mark.parametrize("url", ["https://example.com", "http://example.com",
                                 "https://example.com:8443", "http://example.com:8080"])
def test_standard_web_ports_are_allowed(url):
    validate_url(url)


@pytest.mark.parametrize("url", ["https://example.com:22", "http://example.com:6379",
                                 "http://example.com:25", "https://example.com:3306"])
def test_non_web_ports_are_rejected(url):
    with pytest.raises(SecurityValidationError, match="not allowed"):
        validate_url(url)


# --- PublicOnlyBackend directly ---------------------------------------------

def test_backend_connects_to_the_validated_ip_not_the_hostname():
    backend = PublicOnlyBackend()
    fake, _ = _rebinding_dns("site.test", [PUBLIC_IP])
    seen = {}

    async def fake_inner_connect(host, port, **kwargs):
        seen["host"] = host
        raise httpcore.ConnectError("stop here")

    with patch("socket.getaddrinfo", side_effect=fake), \
         patch.object(backend._inner, "connect_tcp", side_effect=fake_inner_connect):
        with pytest.raises(httpcore.ConnectError):
            asyncio.run(backend.connect_tcp("site.test", 443))
    assert seen["host"] == PUBLIC_IP


def test_backend_rejects_mixed_dns_at_connection_time():
    backend = PublicOnlyBackend()

    def mixed(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]

    with patch("socket.getaddrinfo", side_effect=mixed), \
         patch.object(backend._inner, "connect_tcp") as inner:
        with pytest.raises(SecurityValidationError, match="non-public"):
            asyncio.run(backend.connect_tcp("mixed.test", 443))
    inner.assert_not_called()


def test_backend_rejects_disallowed_port_and_unix_sockets():
    backend = PublicOnlyBackend()
    with pytest.raises(SecurityValidationError, match="not allowed"):
        asyncio.run(backend.connect_tcp("example.com", 22))
    with pytest.raises(SecurityValidationError, match="Unix"):
        asyncio.run(backend.connect_unix_socket("/var/run/docker.sock"))


def test_backend_dns_failure_is_a_controlled_error():
    backend = PublicOnlyBackend()
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("no such host")):
        with pytest.raises(SecurityValidationError, match="Could not resolve"):
            asyncio.run(backend.connect_tcp("does-not-exist.test", 443))


def test_connect_timeout_is_shared_across_all_resolved_ips():
    """Several unreachable IPs must not multiply the timeout (found in live testing)."""
    import time
    backend = PublicOnlyBackend()
    ips = ["93.184.216.34", "93.184.216.35", "93.184.216.36", "93.184.216.37"]

    def many(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]

    budgets = []

    async def slow_connect(host, port, timeout=None, **kwargs):
        budgets.append(timeout)
        await asyncio.sleep(timeout)  # behaves like an unreachable host
        raise httpcore.ConnectTimeout("timed out")

    start = time.monotonic()
    with patch("socket.getaddrinfo", side_effect=many),          patch.object(backend._inner, "connect_tcp", side_effect=slow_connect):
        with pytest.raises(httpcore.ConnectTimeout):
            asyncio.run(backend.connect_tcp("multi.test", 443, timeout=0.4))
    elapsed = time.monotonic() - start

    assert elapsed < 0.8, f"took {elapsed:.2f}s; the 0.4s budget was multiplied"
    assert budgets[0] <= 0.4

