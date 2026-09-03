"""Low-level TLS/SSL probing.

This module performs the actual network work: resolving a host, discovering
which protocol versions it accepts, retrieving its certificate chain, and
enumerating the cipher suites it offers. It deliberately keeps everything at
the socket/``ssl`` level so no external ``openssl`` binary is required.
"""
from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

# Ordered from oldest/weakest to newest/strongest.
PROTOCOL_VERSIONS: list[tuple[str, "ssl.TLSVersion"]] = [
    ("SSLv3", ssl.TLSVersion.SSLv3),
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]

# Protocols considered secure for scoring purposes.
SECURE_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}

# ``SSLSocket.version()`` reports TLS 1.0 as the bare string "TLSv1", not
# "TLSv1.0". Map our display names to the value the socket actually returns
# so protocol-support detection compares like with like.
_VERSION_STRING = {
    "SSLv3": "SSLv3",
    "TLSv1.0": "TLSv1",
    "TLSv1.1": "TLSv1.1",
    "TLSv1.2": "TLSv1.2",
    "TLSv1.3": "TLSv1.3",
}

# Substrings that mark a cipher as weak/broken.
_WEAK_MARKERS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON", "ADH", "AECDH", "IDEA", "SEED")
_FS_MARKERS = ("ECDHE", "DHE")
_AEAD_MARKERS = ("GCM", "CHACHA20", "CCM")

# A curated, security-relevant candidate list for enumeration on TLS <= 1.2.
# Names are OpenSSL cipher names. Unsupported names are skipped gracefully.
CANDIDATE_CIPHERS: list[str] = [
    # Modern AEAD + forward secrecy (strong)
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-CHACHA20-POLY1305",
    # Forward secrecy, CBC (acceptable but weaker)
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-RSA-AES128-SHA",
    "DHE-RSA-AES256-SHA256",
    "DHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA",
    # No forward secrecy (weak key exchange)
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA256",
    "AES128-SHA256",
    "AES256-SHA",
    "AES128-SHA",
    "CAMELLIA256-SHA",
    "CAMELLIA128-SHA",
    # Legacy / broken
    "ECDHE-RSA-DES-CBC3-SHA",
    "DES-CBC3-SHA",
    "IDEA-CBC-SHA",
    "SEED-SHA",
    "RC4-SHA",
    "RC4-MD5",
    "ECDHE-RSA-RC4-SHA",
    "EXP-RC4-MD5",
    "EXP-DES-CBC-SHA",
    "NULL-SHA",
    "NULL-MD5",
    "ADH-AES256-GCM-SHA384",
    "ADH-AES128-SHA",
]


@dataclass
class Cipher:
    name: str
    protocol: str
    bits: Optional[int] = None
    forward_secrecy: bool = False
    strong: bool = True
    aead: bool = False


@dataclass
class ProbeOutcome:
    hostname: str
    port: int
    ip_address: Optional[str] = None
    reachable: bool = False
    error: Optional[str] = None
    supported_protocols: dict[str, bool] = field(default_factory=dict)
    leaf_cert_der: Optional[bytes] = None
    chain_der: list[bytes] = field(default_factory=list)
    ciphers: list[Cipher] = field(default_factory=list)
    negotiated_tls13_cipher: Optional[str] = None


def classify_cipher(name: str, protocol: str, bits: Optional[int]) -> Cipher:
    """Classify a cipher suite by strength / forward secrecy / AEAD."""
    upper = name.upper()
    weak = any(marker in upper for marker in _WEAK_MARKERS)
    # TLS 1.3 suites are always AEAD + forward secrecy and are considered strong.
    if protocol == "TLSv1.3":
        return Cipher(name=name, protocol=protocol, bits=bits,
                      forward_secrecy=True, strong=True, aead=True)
    fs = any(marker in upper for marker in _FS_MARKERS)
    aead = any(marker in upper for marker in _AEAD_MARKERS)
    strong = not weak and (bits or 0) >= 128
    return Cipher(name=name, protocol=protocol, bits=bits,
                  forward_secrecy=fs, strong=strong, aead=aead)


def resolve(hostname: str, port: int, timeout: float) -> Optional[str]:
    """Return the first resolved IP address for ``hostname``, or ``None``."""
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        return infos[0][4][0] if infos else None
    except socket.gaierror:
        return None


def _base_context(min_v: "ssl.TLSVersion", max_v: "ssl.TLSVersion") -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Lower the security level so legacy protocols/ciphers can be *tested*.
    try:
        ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        ctx.minimum_version = min_v
        ctx.maximum_version = max_v
    except (ValueError, OSError):
        pass
    return ctx


def probe_protocol(hostname: str, port: int, version_name: str,
                   version: "ssl.TLSVersion", timeout: float) -> bool:
    """Return True if the server completes a handshake at ``version``."""
    ctx = _base_context(version, version)
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                negotiated = tls.version()
                return negotiated == _VERSION_STRING.get(version_name, version_name)
    except (ssl.SSLError, socket.timeout, OSError, ValueError):
        return False


def fetch_chain(hostname: str, port: int, timeout: float) -> tuple[Optional[bytes], list[bytes], Optional[str]]:
    """Retrieve the leaf certificate and, if possible, the full chain.

    Returns ``(leaf_der, chain_der, negotiated_version)``.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                leaf = tls.getpeercert(binary_form=True)
                chain: list[bytes] = []
                # get_unverified_chain() is available on Python 3.13+.
                getter = getattr(tls, "get_unverified_chain", None)
                if getter is not None:
                    try:
                        chain = [c.public_bytes(_DER) for c in getter()]
                    except Exception:  # pragma: no cover - best effort
                        chain = []
                return leaf, chain, tls.version()
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        return None, [], str(exc)


def _test_cipher(hostname: str, port: int, version: "ssl.TLSVersion",
                 version_name: str, cipher: str, timeout: float) -> Optional[Cipher]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, OSError):
        return None
    try:
        ctx.set_ciphers(f"{cipher}:@SECLEVEL=0")
    except ssl.SSLError:
        return None  # cipher not compiled into this OpenSSL
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                info = tls.cipher()  # (name, protocol, bits)
                if not info:
                    return None
                name, _proto, bits = info
                return classify_cipher(name, version_name, bits)
    except (ssl.SSLError, socket.timeout, OSError, ValueError):
        return None


def enumerate_ciphers(hostname: str, port: int, supported: dict[str, bool],
                      timeout: float, max_workers: int) -> list[Cipher]:
    """Enumerate cipher suites offered across supported legacy protocols."""
    tasks: list[tuple[str, "ssl.TLSVersion", str]] = []
    for name, version in PROTOCOL_VERSIONS:
        if name == "TLSv1.3":
            continue  # TLS 1.3 suites are handled separately.
        if not supported.get(name):
            continue
        for cipher in CANDIDATE_CIPHERS:
            tasks.append((name, version, cipher))

    results: list[Cipher] = []
    seen: set[tuple[str, str]] = set()
    if not tasks:
        return results

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_test_cipher, hostname, port, version, vname, cipher, timeout): None
            for (vname, version, cipher) in tasks
        }
        for future in as_completed(futures):
            cipher = future.result()
            if cipher is None:
                continue
            key = (cipher.protocol, cipher.name)
            if key in seen:
                continue
            seen.add(key)
            results.append(cipher)
    return results


def probe_host(hostname: str, port: int, timeout: float, max_workers: int) -> ProbeOutcome:
    """Perform the full low-level probe for one host."""
    outcome = ProbeOutcome(hostname=hostname, port=port)
    outcome.ip_address = resolve(hostname, port, timeout)
    if outcome.ip_address is None:
        outcome.error = "DNS resolution failed"
        return outcome

    # Probe protocol versions in parallel.
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(probe_protocol, hostname, port, name, version, timeout): name
            for name, version in PROTOCOL_VERSIONS
        }
        for future in as_completed(futures):
            name = futures[future]
            outcome.supported_protocols[name] = future.result()

    if not any(outcome.supported_protocols.values()):
        # Could not negotiate any TLS version; try a plain connect to see if
        # the port is even open, then report accordingly.
        outcome.error = "No SSL/TLS protocol could be negotiated"
        return outcome

    outcome.reachable = True

    # Retrieve the certificate chain.
    leaf, chain, _version = fetch_chain(hostname, port, timeout)
    outcome.leaf_cert_der = leaf
    outcome.chain_der = chain

    # Record the negotiated TLS 1.3 cipher, if supported.
    if outcome.supported_protocols.get("TLSv1.3"):
        cipher = _negotiated_cipher(hostname, port, ssl.TLSVersion.TLSv1_3, timeout)
        if cipher:
            outcome.negotiated_tls13_cipher = cipher.name
            outcome.ciphers.append(cipher)

    # Enumerate legacy protocol ciphers.
    outcome.ciphers.extend(
        enumerate_ciphers(hostname, port, outcome.supported_protocols, timeout, max_workers)
    )
    return outcome


def _negotiated_cipher(hostname: str, port: int, version: "ssl.TLSVersion",
                       timeout: float) -> Optional[Cipher]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, OSError):
        return None
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                info = tls.cipher()
                if not info:
                    return None
                name, _proto, bits = info
                vname = "TLSv1.3" if version == ssl.TLSVersion.TLSv1_3 else tls.version()
                return classify_cipher(name, vname or "TLSv1.3", bits)
    except (ssl.SSLError, socket.timeout, OSError, ValueError):
        return None


# Imported lazily-friendly constant for DER encoding.
from cryptography.hazmat.primitives.serialization import Encoding as _Encoding  # noqa: E402

_DER = _Encoding.DER
