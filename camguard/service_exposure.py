"""Minimal, read-only protocol observations for authorized CCTV services."""
from __future__ import annotations
import socket
import ssl
from typing import Any

HTTP_PORTS = {80, 8080}
TLS_PORTS = {443, 8443}
MAX_RESPONSE_LINE = 512


def _base(ip: str, port: int) -> dict[str, Any]:
    return {
        "device_ip": ip, "transport": "tcp", "port": port,
        "reachability": "reachable", "service_name": None,
        "service_identification": "unknown",
        "service_evidence": "No protocol-level identification attempted for this port.",
        "encryption_status": "unknown", "encryption_evidence": "Encryption was not tested.",
        "evidence_confidence": "low",
        "business_significance": "The TCP port accepted a connection, but the application service and its security properties were not identified.",
        "recommended_action": "Confirm the service and business need with the device administrator; restrict access to authorized systems.",
        "limitations": ["TCP reachability alone does not identify a service or establish vulnerability."],
    }


def unreachable_observation(ip: str, port: int, outcome: str = "not_reachable") -> dict[str, Any]:
    """Represent a bounded TCP check that did not establish a connection."""
    result = _base(ip, port)
    result.update({
        "reachability": outcome,
        "service_evidence": "No TCP connection was established; no service-identification probe was attempted.",
        "encryption_evidence": "Encryption could not be assessed because no TCP connection was established.",
        "evidence_confidence": "high" if outcome == "not_reachable" else "low",
        "business_significance": "The port did not accept a TCP connection during this assessment window. Filtering, device state, or transient network conditions may affect this result.",
        "recommended_action": "No action is indicated from this observation alone. Confirm business requirements and repeat the check if the service is expected.",
        "limitations": ["Not reachable during this check does not prove the service is permanently disabled or inaccessible from other network locations."],
    })
    return result


def _read_status_line(sock: socket.socket) -> bytes:
    data = bytearray()
    while len(data) < MAX_RESPONSE_LINE:
        chunk = sock.recv(1)
        if not chunk or chunk == b"\n":
            break
        if chunk != b"\r":
            data.extend(chunk)
    return bytes(data)


def observe_service(ip: str, port: int, timeout: float = 0.8) -> dict[str, Any]:
    """Identify only conservative HTTP/TLS protocol evidence; never authenticate."""
    result = _base(ip, port)
    if port not in HTTP_PORTS | TLS_PORTS:
        return result
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        raw.settimeout(timeout)
        if port in HTTP_PORTS:
            with raw:
                raw.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode("ascii"))
                line = _read_status_line(raw)
            if line.startswith(b"HTTP/"):
                status = line.decode("ascii", "replace")[:MAX_RESPONSE_LINE]
                result.update({
                    "service_name": "HTTP", "service_identification": "confirmed",
                    "service_evidence": f"Received HTTP status line: {status}",
                    "encryption_status": "plaintext_protocol_observed",
                    "encryption_evidence": "An HTTP response was received over the unencrypted TCP connection; no TLS was used for this observation.",
                    "evidence_confidence": "high",
                    "business_significance": "This endpoint responded using HTTP without transport encryption on this connection. If it carries management traffic, that traffic may be observable on the network path.",
                    "recommended_action": "Prefer HTTPS where supported and restrict management access to trusted administration hosts. Verify the device configuration with its administrator.",
                    "limitations": ["The response does not establish whether authentication is enabled or whether other endpoints use encryption."],
                })
            else:
                result["service_evidence"] = "A TCP connection succeeded, but no valid HTTP status line was observed."
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(raw, server_hostname=None) as secured:
                version = secured.version() or "unknown TLS version"
                cipher = secured.cipher()
                cipher_name = cipher[0] if cipher else "unknown cipher"
            result.update({
                "service_name": "TLS-protected service", "service_identification": "confirmed",
                "service_evidence": f"TLS handshake succeeded; negotiated {version} with {cipher_name}.",
                "encryption_status": "confirmed_tls",
                "encryption_evidence": "A TLS handshake was completed on this TCP endpoint. Certificate trust was not evaluated.",
                "evidence_confidence": "high",
                "business_significance": "The endpoint negotiated TLS, which provides transport encryption for this connection; certificate validity and application-level security still require review.",
                "recommended_action": "Verify the certificate and supported TLS configuration, and confirm that the intended application uses this TLS endpoint.",
                "limitations": ["Certificate trust, application identity, authentication and encryption of other services or video streams were not verified."],
            })
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        result["service_evidence"] = f"Protocol identification was inconclusive: {type(exc).__name__}."
        result["encryption_evidence"] = "No conclusion about encryption can be drawn from this failed or incomplete probe."
    return result
