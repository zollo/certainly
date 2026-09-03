"""Orchestration for analyzing hosts.

``analyze_target`` runs the full pipeline for a single host; ``analyze_targets``
fans out across many hosts using a thread pool (network I/O bound work).
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..models import CipherResult, HostResult, ProtocolResult
from . import tls
from .certificate import parse_certificate
from .http_checks import check_hsts
from .scoring import score_host
from .tls import SECURE_PROTOCOLS


class ParsedTarget:
    __slots__ = ("raw", "hostname", "port")

    def __init__(self, raw: str, hostname: str, port: int):
        self.raw = raw
        self.hostname = hostname
        self.port = port


def parse_target(raw: str, default_port: int) -> ParsedTarget:
    """Parse a user-supplied target into a hostname and port.

    Accepts bare hostnames (``example.com``), host:port (``example.com:8443``),
    and full URLs (``https://example.com/path``).
    """
    value = raw.strip()
    if not value:
        raise ValueError("empty target")

    if "://" in value:
        parsed = urlparse(value)
        hostname = parsed.hostname or ""
        port = parsed.port or default_port
    elif value.count(":") == 1 and not value.startswith("["):
        host, _, port_str = value.partition(":")
        hostname = host
        try:
            port = int(port_str)
        except ValueError:
            hostname = value
            port = default_port
    else:
        hostname = value
        port = default_port

    hostname = hostname.strip().strip("/")
    if not hostname:
        raise ValueError(f"could not parse hostname from {raw!r}")
    return ParsedTarget(raw=raw, hostname=hostname, port=port)


def analyze_target(raw: str, default_port: int, timeout: float,
                   probe_workers: int) -> HostResult:
    """Run the complete analysis pipeline for a single target."""
    start = time.monotonic()
    try:
        target = parse_target(raw, default_port)
    except ValueError as exc:
        return HostResult(
            target=raw, hostname=raw, port=default_port,
            reachable=False, error=str(exc),
            scanned_at=datetime.now(timezone.utc),
        )

    result = HostResult(
        target=raw,
        hostname=target.hostname,
        port=target.port,
        reachable=False,
        scanned_at=datetime.now(timezone.utc),
    )

    outcome = tls.probe_host(target.hostname, target.port, timeout, probe_workers)
    result.ip_address = outcome.ip_address
    result.reachable = outcome.reachable

    if not outcome.reachable:
        result.error = outcome.error
        result.duration_seconds = round(time.monotonic() - start, 3)
        # Still score it (will be F) so the response shape is consistent.
        score_host(result)
        return result

    # Protocols
    result.protocols = [
        ProtocolResult(
            name=name,
            supported=outcome.supported_protocols.get(name, False),
            secure=name in SECURE_PROTOCOLS,
        )
        for name, _version in tls.PROTOCOL_VERSIONS
    ]
    result.supports_tls13 = outcome.supported_protocols.get("TLSv1.3", False)

    # Ciphers
    result.ciphers = [
        CipherResult(
            name=c.name, protocol=c.protocol, bits=c.bits,
            forward_secrecy=c.forward_secrecy, strong=c.strong, aead=c.aead,
        )
        for c in outcome.ciphers
    ]
    result.forward_secrecy = any(c.forward_secrecy for c in outcome.ciphers)

    # Certificate(s)
    if outcome.leaf_cert_der:
        try:
            result.certificate = parse_certificate(outcome.leaf_cert_der, target.hostname)
        except Exception as exc:  # pragma: no cover - malformed cert
            result.error = f"certificate parse error: {exc}"
    for der in outcome.chain_der:
        try:
            result.certificate_chain.append(parse_certificate(der, target.hostname))
        except Exception:  # pragma: no cover
            continue

    # HSTS (application layer)
    hsts = check_hsts(target.hostname, target.port, timeout)
    result.hsts = hsts.present
    result.hsts_max_age = hsts.max_age

    score_host(result)
    result.duration_seconds = round(time.monotonic() - start, 3)
    return result


def analyze_targets(raws: list[str], default_port: int, timeout: float,
                    concurrency: int, probe_workers: int) -> list[HostResult]:
    """Analyze many targets in parallel, preserving input order."""
    if not raws:
        return []
    results: list[HostResult | None] = [None] * len(raws)
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        future_to_index = {
            pool.submit(analyze_target, raw, default_port, timeout, probe_workers): i
            for i, raw in enumerate(raws)
        }
        for future, index in future_to_index.items():
            results[index] = future.result()
    return [r for r in results if r is not None]
