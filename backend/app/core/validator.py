import socket
import ipaddress
from urllib.parse import urlparse
from typing import Iterable, List, Tuple, Optional

# Only standard web ports may be scanned. This keeps the scanner from being
# used to probe arbitrary services (SSH, databases, ...) on public hosts.
ALLOWED_PORTS = {80, 443, 8080, 8443}
_DEFAULT_PORTS = {"http": 80, "https": 443}

# IPv6 ranges that embed an IPv4 address. Python's is_global does not look
# inside them, so e.g. 64:ff9b::7f00:1 (NAT64 for 127.0.0.1) counts as global.
_NAT64_NETWORKS = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
# Deprecated IPv4-compatible (::a.b.c.d) and IPv4-translated (::ffff:0:a.b.c.d) forms.
_BLOCKED_V6_NETWORKS = (ipaddress.ip_network("::/96"), ipaddress.ip_network("::ffff:0:0:0/96"))

class SecurityValidationError(Exception):
    """Custom exception for security-related validation failures."""
    pass

def validate_url(url: str) -> Tuple[str, str]:
    """
    Validates the URL scheme and extracts the hostname.
    Rejects URLs containing username/password credentials for security.

    Args:
        url: The target URL to validate.

    Returns:
        A tuple of (scheme, hostname).

    Raises:
        SecurityValidationError: If the scheme is invalid, credentials are found,
                                 or URL is malformed.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise SecurityValidationError(f"Invalid scheme '{parsed.scheme}'. Only HTTP and HTTPS are allowed.")

        if parsed.username or parsed.password:
            raise SecurityValidationError("URLs containing credentials (username/password) are not allowed.")

        if not parsed.hostname:
            raise SecurityValidationError("URL must contain a valid hostname.")

        # Validate port if present
        if parsed.port is not None:
            if not (0 < parsed.port <= 65535):
                raise SecurityValidationError(f"Invalid port number: {parsed.port}")

        port = parsed.port or _DEFAULT_PORTS[parsed.scheme]
        check_port_allowed(port)

        return parsed.scheme, parsed.hostname
    except Exception as e:
        if isinstance(e, SecurityValidationError):
            raise e
        raise SecurityValidationError(f"Malformed URL: {str(e)}")

def check_port_allowed(port: int) -> None:
    if port not in ALLOWED_PORTS:
        allowed = ", ".join(str(p) for p in sorted(ALLOWED_PORTS))
        raise SecurityValidationError(f"Port {port} is not allowed. Allowed ports: {allowed}.")


def is_public_ip(ip_str: str) -> bool:
    """
    Checks if an IP address is a public, routable address.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if ip.version == 6:
        # Judge IPv6 forms that wrap an IPv4 address by the IPv4 address inside.
        if ip.ipv4_mapped is not None:
            return is_public_ip(str(ip.ipv4_mapped))
        if any(ip in net for net in _NAT64_NETWORKS):
            return is_public_ip(str(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)))
        if any(ip in net for net in _BLOCKED_V6_NETWORKS):
            return False

    # is_global alone is not enough: on some Python versions multicast counts as global.
    if (ip.is_multicast or ip.is_unspecified or ip.is_reserved or ip.is_loopback
            or ip.is_link_local or ip.is_private):
        return False
    return ip.is_global


def check_resolved_ips(hostname: str, ips: Iterable[str]) -> List[str]:
    """
    Validates that EVERY resolved address is public; returns them de-duplicated
    in resolver order. Used both before the request and at connection time.
    """
    unique = list(dict.fromkeys(ips))
    if not unique:
        raise SecurityValidationError(f"Could not resolve hostname: {hostname}")
    for ip in unique:
        if not is_public_ip(ip):
            raise SecurityValidationError(f"Target resolved to a non-public IP: {ip}")
    return unique

def resolve_and_validate_host(hostname: str) -> str:
    """
    Resolves a hostname to all associated IPs (IPv4 and IPv6) and validates
    that EVERY resolved address is public.

    This is an early, user-friendly check. It does NOT by itself stop DNS
    rebinding: the real enforcement happens at connection time in
    app.core.safe_transport, which re-resolves and connects to a checked IP.
    """
    try:
        # getaddrinfo returns a list of 5-tuples. The 5th element is (address, port).
        # This resolves both IPv4 and IPv6.
        addr_info = socket.getaddrinfo(hostname, None)
        resolved_ips = check_resolved_ips(hostname, (item[4][0] for item in addr_info))
        return resolved_ips[0]
    except socket.gaierror:
        raise SecurityValidationError(f"Could not resolve hostname: {hostname}")
    except Exception as e:
        if isinstance(e, SecurityValidationError):
            raise e
        raise SecurityValidationError(f"DNS resolution error: {str(e)}")

def validate_target(url: str) -> Tuple[str, str]:
    """
    Full validation pipeline for a target URL.

    1. Validates scheme.
    2. Resolves hostname to IP.
    3. Validates IP is public.

    Returns:
        A tuple of (scheme, validated_ip).
    """
    scheme, hostname = validate_url(url)
    validated_ip = resolve_and_validate_host(hostname)
    return scheme, validated_ip
