"""Conservative TCP inventory for explicitly authorized RFC1918 IPv4 scopes."""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

CAMERA_PORTS: dict[int, str] = {
    80: "HTTP management",
    443: "HTTPS management",
    554: "RTSP service (port only; no stream access)",
    8000: "Vendor management/API (varies by vendor)",
    8080: "Alternate HTTP management",
    8443: "Alternate HTTPS management",
    8899: "Vendor service (varies by vendor)",
    34567: "Vendor service (varies by vendor)",
    37777: "Vendor service (varies by vendor)",
}
RFC1918 = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
MAX_ADDRESSES = 256
MAX_WORKERS = 32
MAX_TIMEOUT = 2.0


class ScopeError(ValueError):
    """Raised when a requested scan scope exceeds safety boundaries."""


def validate_scope(cidr: str, authorized: bool, max_addresses: int = MAX_ADDRESSES):
    if not authorized:
        raise ScopeError("Authorization confirmation is required (--authorized).")
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ScopeError(f"Invalid network: {exc}") from exc
    if network.version != 4:
        raise ScopeError("Only IPv4 scopes are supported in this MVP.")
    if not any(network.subnet_of(allowed) for allowed in RFC1918):
        raise ScopeError("Only RFC1918 private IPv4 networks (10/8, 172.16/12, 192.168/16) are allowed.")
    if network.num_addresses > max_addresses:
        raise ScopeError(f"Scope contains {network.num_addresses} addresses; maximum is {max_addresses}.")
    hosts = list(network.hosts())
    if not hosts:
        raise ScopeError("Scope contains no usable host addresses.")
    return network, hosts


def _check_host(host: str, ports: dict[int, str], timeout: float) -> dict[str, Any]:
    opened = []
    for port, service in ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((host, port)) == 0:
                opened.append({"port": port, "service": service})
        except OSError:
            pass
        finally:
            sock.close()
    return {"ip": host, "open_ports": opened, "observed_at": datetime.now(timezone.utc).isoformat()}


def scan_network(cidr: str, authorized: bool, timeout: float = 0.8, workers: int = 16) -> dict[str, Any]:
    network, hosts = validate_scope(cidr, authorized)
    if not 0.1 <= timeout <= MAX_TIMEOUT:
        raise ScopeError(f"Timeout must be between 0.1 and {MAX_TIMEOUT} seconds.")
    if not 1 <= workers <= MAX_WORKERS:
        raise ScopeError(f"Workers must be between 1 and {MAX_WORKERS}.")
    assets = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_check_host, str(ip), CAMERA_PORTS, timeout) for ip in hosts]
        for future in as_completed(futures):
            result = future.result()
            if result["open_ports"]:
                assets.append(result)
    assets.sort(key=lambda item: ipaddress.ip_address(item["ip"]))
    findings = []
    for asset in assets:
        for port in asset["open_ports"]:
            if port["port"] in (80, 8080):
                severity, title = "medium", "HTTP management service reachable"
                recommendation = "Confirm whether HTTP is required; prefer HTTPS and restrict management access to trusted administration hosts."
            elif port["port"] in (8000, 8899, 34567, 37777):
                severity, title = "medium", "Vendor-specific service reachable"
                recommendation = "Identify the vendor and service, confirm business need, and restrict access at the network boundary."
            elif port["port"] == 554:
                severity, title = "low", "RTSP service reachable"
                recommendation = "Confirm RTSP is required and restrict it to authorized viewing/recording systems. CamGuard did not access any stream."
            else:
                severity, title = "info", "Management or camera service reachable"
                recommendation = "Confirm the service is expected and restrict access to approved management systems."
            findings.append({
                "asset_ip": asset["ip"], "port": port["port"], "service": port["service"],
                "severity": severity, "title": title, "evidence": f"TCP connection succeeded on {port['port']}.",
                "recommendation": recommendation,
            })
    return {
        "tool": "TrinTech CamGuard", "version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": {"cidr": str(network), "addresses_considered": len(hosts), "authorization_attested": True},
        "scan_type": "bounded TCP reachability checks; no authentication or exploitation",
        "assets": assets, "findings": findings,
        "limitations": [
            "Open TCP ports do not establish that a device is vulnerable.",
            "Device identity, firmware, TLS configuration, and CVE status are not verified by this MVP.",
            "Only responsive hosts with at least one listed TCP port are included.",
        ],
    }
