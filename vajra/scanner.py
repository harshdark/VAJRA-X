import json
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests

from .safety import normalize_url, resolve_public_addresses, validate_redirect_url, SafetyError

TIMEOUT = 8
USER_AGENT = "VAJRA-X-v0.1-Authorized-Security-Assessment/0.1"

SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "MEDIUM", "HTTP Strict Transport Security is missing.",
        "Enable HSTS after confirming HTTPS works across the entire site."
    ),
    "Content-Security-Policy": (
        "MEDIUM", "Content Security Policy is missing.",
        "Define a restrictive Content-Security-Policy appropriate for the application."
    ),
    "X-Content-Type-Options": (
        "LOW", "X-Content-Type-Options is missing.",
        "Set X-Content-Type-Options: nosniff."
    ),
    "Referrer-Policy": (
        "LOW", "Referrer-Policy is missing.",
        "Set a suitable Referrer-Policy, such as strict-origin-when-cross-origin."
    ),
    "Permissions-Policy": (
        "INFO", "Permissions-Policy is missing.",
        "Consider restricting browser features the application does not use."
    ),
    "X-Frame-Options": (
        "LOW", "X-Frame-Options is missing.",
        "Use frame-ancestors in CSP; optionally add X-Frame-Options for legacy browsers."
    ),
}

def dns_lookup(host):
    records = {}
    for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            import dns.resolver
            answers = dns.resolver.resolve(host, record_type, lifetime=4)
            records[record_type] = [str(answer) for answer in answers]
        except Exception:
            records[record_type] = []
    return records

def tls_info(host, port=443):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure:
                cert = secure.getpeercert()
                cipher = secure.cipher()
                return {
                    "verified": True,
                    "protocol": secure.version(),
                    "cipher": cipher[0] if cipher else None,
                    "subject": str(cert.get("subject")),
                    "issuer": str(cert.get("issuer")),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "subject_alt_names": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"][:50],
                }
    except Exception as exc:
        return {"verified": False, "error": str(exc)}

def safe_get(url):
    current = url
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    for _ in range(4):
        validate_redirect_url(current)
        response = session.get(current, timeout=TIMEOUT, allow_redirects=False, stream=True)
        # Do not download large response bodies.
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                return None
            current = urljoin(current, location)
            continue
        # Read at most 256 KB for a minimal technology fingerprint.
        body = response.raw.read(262144, decode_content=True)
        info = {
            "final_url": current,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_type": response.headers.get("Content-Type"),
            "server": response.headers.get("Server"),
            "body_sample": body.decode(response.encoding or "utf-8", errors="replace"),
            "cookies": response.cookies,
        }
        response.close()
        return info
    raise SafetyError("Too many redirects.")

def technology_indicators(http):
    headers = http.get("headers", {})
    body = http.get("body_sample", "").lower()
    indicators = []
    server = headers.get("Server")
    powered = headers.get("X-Powered-By")
    if server:
        indicators.append({"source": "Server header", "value": server})
    if powered:
        indicators.append({"source": "X-Powered-By header", "value": powered})
    signatures = [
        ("WordPress", "wp-content"),
        ("Drupal", "drupal.settings"),
        ("Joomla", "/media/system/js/"),
        ("React", "react"),
        ("Next.js", "__next"),
        ("Laravel", "laravel_session"),
    ]
    for name, marker in signatures:
        if marker in body:
            indicators.append({"source": "HTML body indicator", "value": name})
    return indicators

def build_findings(http, tls, dns):
    findings = []
    headers = http.get("headers", {})
    for header, (severity, description, recommendation) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({
                "category": "HTTP Security Headers",
                "severity": severity,
                "title": f"Missing {header}",
                "description": description,
                "recommendation": recommendation,
                "confidence": "High",
            })

    cookies = http.get("headers", {}).get("Set-Cookie", "")
    if cookies:
        cookie_lower = cookies.lower()
        if "secure" not in cookie_lower:
            findings.append({
                "category": "Cookie Security",
                "severity": "LOW",
                "title": "Cookie may be missing Secure attribute",
                "description": "The observed Set-Cookie header does not visibly include the Secure attribute.",
                "recommendation": "Set Secure on cookies that should only travel over HTTPS.",
                "confidence": "Medium",
            })
        if "httponly" not in cookie_lower:
            findings.append({
                "category": "Cookie Security",
                "severity": "LOW",
                "title": "Cookie may be missing HttpOnly attribute",
                "description": "The observed Set-Cookie header does not visibly include HttpOnly.",
                "recommendation": "Set HttpOnly on session cookies that do not require JavaScript access.",
                "confidence": "Medium",
            })

    final_url = http.get("final_url", "")
    if final_url.startswith("http://"):
        findings.append({
            "category": "Transport Security",
            "severity": "MEDIUM",
            "title": "Final page uses HTTP",
            "description": "The final response URL uses unencrypted HTTP.",
            "recommendation": "Serve the application over HTTPS and redirect HTTP to HTTPS.",
            "confidence": "High",
        })
    if final_url.startswith("https://") and not tls.get("verified", False):
        findings.append({
            "category": "TLS",
            "severity": "HIGH",
            "title": "TLS certificate verification failed",
            "description": tls.get("error", "TLS verification could not be completed."),
            "recommendation": "Inspect certificate validity, hostname coverage and certificate chain.",
            "confidence": "Medium",
        })
    return findings

def risk_summary(findings):
    weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 0}
    score = min(100, sum(weights.get(f["severity"], 0) for f in findings))
    if score >= 25:
        rating = "HIGH"
    elif score >= 10:
        rating = "MEDIUM"
    elif score > 0:
        rating = "LOW"
    else:
        rating = "NO ISSUES DETECTED"
    return {"risk": rating, "score": score, "findings": len(findings)}

def crt_subdomains(domain):
    # Public Certificate Transparency lookup. This is passive data retrieval.
    url = "https://crt.sh/"
    try:
        response = requests.get(
            url,
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": USER_AGENT},
            timeout=12,
        )
        if response.status_code != 200:
            return []
        data = response.json()
        found = set()
        for item in data:
            for name in item.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name == domain or name.endswith("." + domain):
                    found.add(name)
        return sorted(found)[:200]
    except Exception:
        return []

def run_assessment(target):
    normalized = normalize_url(target)
    parsed = urlparse(normalized)
    host = parsed.hostname.lower().rstrip(".")
    ips = resolve_public_addresses(host)

    dns = dns_lookup(host)
    dns["public_ips"] = ips

    http_raw = safe_get(normalized)
    if not http_raw:
        raise RuntimeError("No HTTP response received.")

    final_parsed = urlparse(http_raw["final_url"])
    tls = tls_info(final_parsed.hostname, final_parsed.port or 443) if final_parsed.scheme == "https" else {
        "verified": False, "error": "Final URL is not HTTPS."
    }

    http = {
        "final_url": http_raw["final_url"],
        "status_code": http_raw["status_code"],
        "content_type": http_raw["content_type"],
        "server": http_raw["server"],
        "headers": http_raw["headers"],
    }
    technology = technology_indicators(http_raw)
    findings = build_findings(http, tls, dns)
    return {
        "tool": "VAJRA-X",
        "version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": normalized,
        "scope_note": "Run only with explicit authorization. Limited non-destructive assessment.",
        "dns": dns,
        "tls": tls,
        "http": http,
        "technology": technology,
        "subdomains": crt_subdomains(host),
        "findings": findings,
        "summary": risk_summary(findings),
    }
