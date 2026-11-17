"""Conservative TCP inventory for explicitly authorized RFC1918 IPv4 scopes."""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from uuid import uuid4
from typing import Any

from .service_exposure import observe_service, unreachable_observation
from . import __version__

CAMERA_PORTS: dict[int, str] = {
    80: "HTTP management (port hint only)",
    443: "HTTPS management (port hint only)",
    554: "RTSP (port hint only; no stream access)",
    8000: "Vendor service (port hint only)",
    8080: "Alternate HTTP (port hint only)",
    8443: "Alternate HTTPS (port hint only)",
    8899: "Vendor service (port hint only)",
    34567: "Vendor service (port hint only)",
    37777: "Vendor service (port hint only)",
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
    observations = []
    for port, service_hint in ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            status = sock.connect_ex((host, port))
            if status == 0:
                observation = observe_service(host, port, timeout)
                opened.append({
                    "port": port,
                    "service": service_hint,
                    "port_hint": service_hint,
                    "service_observation": observation,
                })
                observations.append(observation)
            else:
                observations.append(unreachable_observation(host, port, "not_reachable"))
        except OSError:
            observations.append(unreachable_observation(host, port, "error"))
        finally:
            sock.close()
    return {
        "ip": host,
        "open_ports": opened,
        "port_observations": observations,
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }


def scan_network(cidr: str, authorized: bool, timeout: float = 0.8, workers: int = 16) -> dict[str, Any]:
    network, hosts = validate_scope(cidr, authorized)
    if not 0.1 <= timeout <= MAX_TIMEOUT:
        raise ScopeError(f"Timeout must be between 0.1 and {MAX_TIMEOUT} seconds.")
    if not 1 <= workers <= MAX_WORKERS:
        raise ScopeError(f"Workers must be between 1 and {MAX_WORKERS}.")
    assets = []
    host_results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_check_host, str(ip), CAMERA_PORTS, timeout) for ip in hosts]
        for future in as_completed(futures):
            result = future.result()
            host_results.append(result)
            if result["open_ports"]:
                assets.append(result)
    assets.sort(key=lambda item: ipaddress.ip_address(item["ip"]))

    # Only create a service finding when protocol evidence supports it. A port
    # number or TCP connection alone never confirms HTTP, RTSP, or a vulnerability.
    findings = []
    for asset in assets:
        for port_record in asset["open_ports"]:
            observation = port_record.get("service_observation", {})
            if (
                observation.get("service_name") == "HTTP"
                and observation.get("encryption_status") == "plaintext_protocol_observed"
            ):
                findings.append({
                    "asset_ip": asset["ip"],
                    "port": port_record["port"],
                    "service": "HTTP",
                    "severity": "low",
                    "title": "HTTP response observed without transport encryption",
                    "evidence": observation.get("service_evidence", "HTTP response observed."),
                    "recommendation": observation.get(
                        "recommended_action",
                        "Prefer HTTPS where supported and restrict management access.",
                    ),
                    "source": "CamGuard protocol observation",
                })

    assessment_id = str(uuid4())
    service_observations = []
    for host_result in host_results:
        for observation in host_result.get("port_observations", []):
            observation.update({
                "schema_version": "1.0",
                "assessment_id": assessment_id,
                "asset_id": f"asset:{host_result['ip']}",
                "observed_at": host_result["observed_at"],
            })
            service_observations.append(observation)

    return {
        "tool": "TrinTech CamGuard",
        "version": __version__,
        "assessment_id": assessment_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "cidr": str(network),
            "addresses_considered": len(hosts),
            "authorization_attested": True,
        },
        "scan_type": "bounded TCP reachability and minimal protocol observations; no authentication or exploitation",
        "assets": assets,
        "findings": findings,
        "service_observations": service_observations,
        "limitations": [
            "Open TCP ports do not establish that a device is vulnerable.",
            "Device identity, firmware, certificate trust, authentication, and CVE status are not verified by this assessment.",
            "Service identification is attempted only for HTTP on ports 80/8080 and TLS handshakes on ports 443/8443; other ports remain unidentified.",
            "A TLS handshake confirms encryption for that endpoint only; it does not prove video-stream or all application traffic is encrypted.",
            "The asset inventory lists responsive hosts; service observations also record non-reachable and error outcomes for each checked port.",
        ],
    }
