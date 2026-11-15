"""Bounded unauthenticated HTTPS metadata collection for approved camera IPs."""
from __future__ import annotations
import html, ipaddress, re, urllib.error, urllib.request
from datetime import datetime, timezone
from typing import Any

RFC1918 = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"))
MAX_TARGETS, MAX_TIMEOUT, MAX_BODY = 64, 2.0, 16384

class MetadataScopeError(ValueError):
    """Unsafe or invalid metadata collection scope."""

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

_SIGNATURES = (
    ("Axis", ("axis", "axis communications")),
    ("Hikvision", ("hikvision", "hikvision web")),
    ("Dahua", ("dahua", "dahua technology")),
    ("Hanwha Vision", ("hanwha", "samsung techwin")),
    ("Uniview", ("uniview", "unv")),
)

def validate_targets(targets: list[str], authorized: bool) -> list[str]:
    if not authorized:
        raise MetadataScopeError("Written authorization is required (--authorized).")
    if not isinstance(targets, list) or not targets or len(targets) > MAX_TARGETS:
        raise MetadataScopeError(f"Provide 1–{MAX_TARGETS} explicitly approved IP addresses.")
    result = []
    for raw in targets:
        try:
            ip = ipaddress.ip_address(str(raw).strip())
        except ValueError as exc:
            raise MetadataScopeError(f"Invalid IP address: {raw}") from exc
        if ip.version != 4 or not any(ip in net for net in RFC1918):
            raise MetadataScopeError(f"Target {ip} is outside allowed RFC1918 IPv4 scope.")
        if str(ip) not in result:
            result.append(str(ip))
    return result

def _title(body: bytes) -> str | None:
    text = body.decode("utf-8", errors="replace")
    match = re.search(r"<title[^>]*>(.*?)</title\\s*>", text, re.I | re.S)
    if not match:
        return None
    value = html.unescape(re.sub(r"<[^>]+>", "", match.group(1)))
    return re.sub(r"\\s+", " ", value).strip()[:160] or None

def identify(server: str, title: str | None) -> tuple[str | None, str, list[str]]:
    for vendor, signatures in _SIGNATURES:
        for signature in signatures:
            if signature in server.lower():
                return vendor, "medium", [f"HTTP Server header contains signature: {signature}"]
            if title and signature in title.lower():
                return vendor, "low", [f"HTML title contains signature: {signature}"]
    return None, "none", ["No supported manufacturer signature found."]

def collect_metadata(targets: list[str], authorized: bool, timeout: float = 1.0) -> dict[str, Any]:
    hosts = validate_targets(targets, authorized)
    if not 0.1 <= timeout <= MAX_TIMEOUT:
        raise MetadataScopeError(f"Timeout must be between 0.1 and {MAX_TIMEOUT} seconds.")
    opener = urllib.request.build_opener(_NoRedirect)
    results = []
    for host in hosts:
        url = f"https://{host}/"
        req = urllib.request.Request(url, headers={
            "User-Agent": "TrinTech-CamGuard-Metadata/0.3",
            "Accept": "text/html,application/xhtml+xml",
            "Range": f"bytes=0-{MAX_BODY-1}",
        }, method="GET")
        item = {
            "ip": host, "url": url, "request": "GET /",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "manufacturer": None, "manufacturer_confidence": "none",
            "model": None, "firmware": None, "evidence": [],
            "limitations": ["Unauthenticated root-page metadata only; model and firmware are not inferred."],
        }
        try:
            with opener.open(req, timeout=timeout) as response:
                status, headers, body = response.status, response.headers, response.read(MAX_BODY)
        except urllib.error.HTTPError as exc:
            status, headers = exc.code, exc.headers
            body = exc.read(MAX_BODY) if exc.code in (401,403) else b""
            item["limitations"].append("Access-denied/error response; no authentication was attempted.")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            item["error"] = type(exc).__name__
            item["evidence"] = ["HTTPS request failed; no identity conclusion made."]
            results.append(item)
            continue
        server = str(headers.get("Server", ""))[:200]
        title = None
        if body:
            match = re.search(r"<title[^>]*>(.*?)</title\\s*>", body.decode("utf-8", "replace"), re.I | re.S)
            if match:
                title = re.sub(r"\\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", match.group(1)))).strip()[:160]
        vendor, confidence, evidence = identify(server, title)
        item.update(http_status=status, server_header=server or None, page_title=title,
                    manufacturer=vendor, manufacturer_confidence=confidence,
                    evidence=evidence + [f"HTTPS GET / returned HTTP {status}."])
        results.append(item)
    return {
        "tool": "TrinTech CamGuard",
        "collection": "one unauthenticated HTTPS GET / per explicitly approved IP; redirects disabled",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "authorization_attested": True, "targets": results,
        "confidence_guide": {"medium": "Signature in Server header; corroborate manually.",
                             "low": "Signature in HTML title only; weak indicator.",
                             "none": "No supported signature; identity remains unknown."},
        "safety": ["RFC1918 IPv4 allowlist only; maximum 64 targets.",
                   "No credentials, vendor API paths, RTSP streams, config endpoints, or writes.",
                   "TLS certificate verification remains enabled; no insecure fallback."],
    }
