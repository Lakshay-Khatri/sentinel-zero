import pytest
import socket
from unittest.mock import patch
from app.core.validator import validate_target, SecurityValidationError, is_public_ip

def test_validate_url_valid():
    with patch('app.core.validator.resolve_and_validate_host') as mock_resolve:
        mock_resolve.return_value = "8.8.8.8"
        scheme, ip = validate_target("https://google.com")
        assert scheme == "https"
        assert ip == "8.8.8.8"

def test_validate_url_invalid_scheme():
    with pytest.raises(SecurityValidationError, match="Invalid scheme"):
        validate_target("ftp://google.com")

def test_validate_url_malformed():
    with pytest.raises(SecurityValidationError):
        validate_target("not-a-url")

def test_is_public_ip_valid():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("1.1.1.1") is True
    assert is_public_ip("2606:4700:4700::1111") is True # Cloudflare IPv6

def test_is_public_ip_private():
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("172.16.0.1") is False
    assert is_public_ip("169.254.0.1") is False
    assert is_public_ip("0.0.0.0") is False

def test_is_public_ip_ipv6_private():
    assert is_public_ip("::1") is False
    assert is_public_ip("fe80::1") is False
    assert is_public_ip("fc00::1") is False

def test_is_public_ip_ipv4_mapped_ipv6():
    """Verify that IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1) are rejected."""
    assert is_public_ip("::ffff:127.0.0.1") is False
    assert is_public_ip("::ffff:192.168.1.1") is False
    assert is_public_ip("::ffff:8.8.8.8") is True

def test_dns_resolution_failure():
    with patch('socket.getaddrinfo') as mock_dns:
        mock_dns.side_effect = socket.gaierror
        with pytest.raises(SecurityValidationError, match="Could not resolve hostname"):
            validate_target("https://this.domain.does.not.exist.invalid")

def test_dns_resolution_private_ip():
    with patch('socket.getaddrinfo') as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0))
        ]
        with pytest.raises(SecurityValidationError, match="resolved to a non-public IP"):
            validate_target("https://localhost")

def test_dns_resolution_public_ip():
    with patch('socket.getaddrinfo') as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))
        ]
        scheme, ip = validate_target("https://example.com")
        assert scheme == "https"
        assert ip == "93.184.216.34"

def test_dns_resolution_ipv6_public():
    with patch('socket.getaddrinfo') as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2606:4700:4700::1111', 0, 0, 0))
        ]
        scheme, ip = validate_target("https://ipv6.google.com")
        assert scheme == "https"
        assert ip == "2606:4700:4700::1111"

def test_dns_mixed_results():
    """If any resolved IP is private, the whole hostname must be rejected."""
    with patch('socket.getaddrinfo') as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0))
        ]
        with pytest.raises(SecurityValidationError, match="resolved to a non-public IP"):
            validate_target("https://mixed-dns.com")

def test_url_with_credentials():
    """URLs with username/password must be rejected."""
    with pytest.raises(SecurityValidationError, match="credentials"):
        validate_target("https://admin:password@google.com")

def test_url_malformed_port():
    """Ports outside the valid range must be rejected."""
    with pytest.raises(SecurityValidationError, match="Port out of range"):
        validate_target("https://google.com:70000")

def test_url_missing_hostname():
    """URLs missing a hostname should be rejected."""
    with pytest.raises(SecurityValidationError):
        validate_target("https://")

def test_url_invalid_host():
    """URLs with syntactically invalid hosts should be rejected."""
    with pytest.raises(SecurityValidationError):
        validate_target("https://[invalid_ipv6]")
