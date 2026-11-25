import ipaddress
import socket
from urllib.parse import urlparse

class SafetyError(ValueError):
    pass

def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise SafetyError("Please enter a target URL.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise SafetyError("Only http:// and https:// targets are supported.")
    if not parsed.hostname:
        raise SafetyError("The URL does not contain a valid hostname.")
    if parsed.username or parsed.password:
        raise SafetyError("URLs containing embedded credentials are not supported.")
    if parsed.port and not (1 <= parsed.port <= 65535):
        raise SafetyError("Invalid port.")
    return value

def resolve_public_addresses(hostname: str):
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SafetyError(f"DNS resolution failed: {exc}") from exc

    addresses = sorted({item[4][0] for item in infos})
    if not addresses:
        raise SafetyError("No IP addresses were returned.")

    parsed = []
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise SafetyError(
                f"Target resolves to a non-public address ({address}). "
                "Private, loopback, link-local and reserved destinations are blocked."
            )
        parsed.append(address)
    return parsed

def validate_redirect_url(url: str):
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    resolve_public_addresses(parsed.hostname)
    return normalized
