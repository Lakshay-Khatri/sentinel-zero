import socket
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, Optional

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

        return parsed.scheme, parsed.hostname
    except Exception as e:
        if isinstance(e, SecurityValidationError):
            raise e
        raise SecurityValidationError(f"Malformed URL: {str(e)}")

def is_public_ip(ip_str: str) -> bool:
    """
    Checks if an IP address is a public, routable address.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global
    except ValueError:
        return False

def resolve_and_validate_host(hostname: str) -> str:
    """
    Resolves a hostname to all associated IPs (IPv4 and IPv6) and validates
    that EVERY resolved address is public.

    To prevent DNS Rebinding, the calling code MUST use the IP returned by
    this function for the actual connection, rather than the hostname.
    """
    try:
        # getaddrinfo returns a list of 5-tuples. The 5th element is (address, port).
        # This resolves both IPv4 and IPv6.
        addr_info = socket.getaddrinfo(hostname, None)

        resolved_ips = set()
        for item in addr_info:
            ip = item[4][0]
            resolved_ips.add(ip)

        # Validate every single IP associated with the hostname
        for ip in resolved_ips:
            if not is_public_ip(ip):
                raise SecurityValidationError(f"Target resolved to a non-public IP: {ip}")

        # Return the first validated IP for the connection
        return list(resolved_ips)[0]
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
