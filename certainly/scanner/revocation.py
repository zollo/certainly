"""Validated, SSRF-hardened live OCSP revocation checking.

The OCSP responder URL comes from the scanned certificate's AIA extension, so
it is attacker-influenced. Every request is therefore guarded against SSRF
(scheme allow-list, globally-routable-address check, address pinning against
DNS rebinding, no redirects, bounded response), and every response is
cryptographically validated before its status is trusted:

* the issuer used for the check is proven to have issued the leaf (name
  chaining, CA basic constraints, keyCertSign, verified signature) — the TLS
  chain and AIA bundle are untrusted (the probe connection is unverified),
* the response is SUCCESSFUL,
* its CertID matches this exact leaf + issuer,
* it is fresh (a bounded thisUpdate/nextUpdate window), and
* it is signed by the issuer directly, or by a delegated responder certificate
  that is itself issuer-signed and carries the id-kp-OCSPSigning EKU.

Any failure, uncertainty, or unreachable/forbidden responder yields
``unavailable`` — an unverified response can never set the revocation status.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

_DER = serialization.Encoding.DER
_MAX_RESPONSE_BYTES = 64 * 1024
_CLOCK_SKEW = timedelta(minutes=5)


# --- SSRF guard: resolve once, allow only public addresses, pin on connect ---

def _resolve_public(host: str) -> Optional[list[str]]:
    """Resolve ``host`` and return its addresses only if *all* of them are
    globally routable, else ``None``.

    ``is_global`` is used rather than a private/loopback deny-list so that
    shared/CGNAT space (``100.64.0.0/10``, which includes cloud metadata
    endpoints), benchmarking ranges, and other non-public-but-not-"private"
    blocks are refused too.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    addrs: list[str] = []
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:  # pragma: no cover - defensive
            return None
        if not ip.is_global:
            return None
        if info[4][0] not in addrs:
            addrs.append(info[4][0])
    return addrs or None


def _is_public_host(host: str) -> bool:
    """True only if every resolved address for ``host`` is globally routable."""
    return _resolve_public(host) is not None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that dials a pre-validated IP while keeping the Host
    header, so a hostname cannot re-resolve to a private address between the
    SSRF check and the connect (DNS rebinding)."""

    def __init__(self, host: str, pinned_ip: str, **kwargs):
        super().__init__(host, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS variant: dials the pinned IP but keeps the hostname for the Host
    header, the TLS SNI, and certificate validation."""

    def __init__(self, host: str, pinned_ip: str, **kwargs):
        super().__init__(host, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self):
        sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout
        )
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _safe_open(url: str, timeout: float, data: Optional[bytes] = None,
               content_type: Optional[str] = None) -> Optional[bytes]:
    """SSRF-guarded HTTP(S) fetch: public host only, address-pinned, no
    redirects (http.client never follows them), size-capped."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    addrs = _resolve_public(parsed.hostname)
    if not addrs:
        return None
    pinned = addrs[0]
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    headers = {"User-Agent": "Certainly/1.0"}
    if content_type:
        headers["Content-Type"] = content_type

    conn: Optional[http.client.HTTPConnection] = None
    try:
        if parsed.scheme == "https":
            conn = _PinnedHTTPSConnection(
                host, pinned, port=port, timeout=timeout,
                context=ssl.create_default_context(),
            )
        else:
            conn = _PinnedHTTPConnection(host, pinned, port=port, timeout=timeout)
        conn.request("POST" if data else "GET", path, body=data, headers=headers)
        response = conn.getresponse()
        if response.status != 200:  # a 3xx is not followed — treated as failure
            return None
        raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except Exception:
        return None
    finally:
        if conn is not None:
            conn.close()
    if len(raw) > _MAX_RESPONSE_BYTES:
        return None
    return raw


# --- issuer validation: the probe chain / AIA bundle is untrusted -----------

def _issued(leaf: x509.Certificate, candidate: x509.Certificate) -> bool:
    """True if ``candidate`` is a CA that actually issued ``leaf``.

    The TLS chain comes from an unverified (``CERT_NONE``) probe and the AIA
    caIssuers bundle is attacker-influenced, so the candidate's key must not be
    trusted for CertID/OCSP-signature purposes until it is proven to have
    signed the leaf. Checks CA basic constraints, keyCertSign (when present),
    name chaining, and the signature over the leaf.
    """
    try:
        bc = candidate.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not bc.ca:
            return False
    except x509.ExtensionNotFound:
        return False
    try:
        ku = candidate.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ku.key_cert_sign:
            return False
    except x509.ExtensionNotFound:
        pass  # KeyUsage is optional; absence is not disqualifying.
    try:
        # Verifies issuer/subject name chaining and the signature (handles
        # RSA/PSS/ECDSA/EdDSA); raises on any mismatch.
        leaf.verify_directly_issued_by(candidate)
    except Exception:
        return False
    return True


def select_issuer(leaf_der: bytes, candidate_ders: list[bytes]) -> Optional[bytes]:
    """Return the DER of the first candidate that provably issued ``leaf_der``."""
    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
    except Exception:
        return None
    for der in candidate_ders:
        try:
            cand = x509.load_der_x509_certificate(der)
        except Exception:
            continue
        if _issued(leaf, cand):
            return cand.public_bytes(_DER)
    return None


def _as_utc(value) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _verify_signature(pubkey, signature: bytes, data: bytes, hash_algo) -> bool:
    try:
        if isinstance(pubkey, rsa.RSAPublicKey):
            pubkey.verify(signature, data, padding.PKCS1v15(), hash_algo)
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(signature, data, ec.ECDSA(hash_algo))
        elif isinstance(pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pubkey.verify(signature, data)
        else:
            return False
        return True
    except Exception:
        return False


def _responder_keys(response: "ocsp.OCSPResponse", issuer: x509.Certificate) -> list:
    """Return every public key authorised to have signed ``response``.

    The issuer may always sign directly, so its key is always a candidate (an
    issuer-signed response may legally embed the issuer certificate, which lacks
    the OCSP-signing EKU — that must not disable the direct-issuer path). In
    addition, any embedded certificate that is issuer-signed, carries the
    id-kp-OCSPSigning EKU, and is time-valid is an authorised delegated
    responder.
    """
    keys = [issuer.public_key()]
    now = datetime.now(timezone.utc)
    for cert in (response.certificates or []):
        # Must be signed by the issuer.
        if not _verify_signature(issuer.public_key(), cert.signature,
                                  cert.tbs_certificate_bytes,
                                  cert.signature_hash_algorithm):
            continue
        # Must be an authorised OCSP responder.
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            continue
        if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
            continue
        not_before = _as_utc(cert.not_valid_before_utc)
        not_after = _as_utc(cert.not_valid_after_utc)
        if not_before - _CLOCK_SKEW > now or not_after + _CLOCK_SKEW < now:
            continue
        keys.append(cert.public_key())
    return keys


def _expected_certid(leaf: x509.Certificate, issuer: x509.Certificate, hash_algo):
    req = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hash_algo).build()
    return req.serial_number, req.issuer_key_hash, req.issuer_name_hash


def validate_response(raw: bytes, leaf: x509.Certificate,
                      issuer: x509.Certificate) -> str:
    """Validate a DER OCSP response for ``leaf``/``issuer`` and return its status.

    Returns ``good`` / ``revoked`` / ``unknown`` only after full validation;
    ``unavailable`` on any failure.
    """
    try:
        response = ocsp.load_der_ocsp_response(raw)
    except Exception:
        return "unavailable"
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return "unavailable"

    # CertID must match this exact leaf + issuer (recomputed with the
    # response's own hash algorithm so the hashes are comparable).
    try:
        exp_serial, exp_key_hash, exp_name_hash = _expected_certid(
            leaf, issuer, response.hash_algorithm
        )
        if (response.serial_number != exp_serial
                or response.issuer_key_hash != exp_key_hash
                or response.issuer_name_hash != exp_name_hash):
            return "unavailable"
    except Exception:
        return "unavailable"

    # Freshness. A missing nextUpdate leaves no upper bound, which would let a
    # captured "good" response be replayed indefinitely after revocation, so it
    # is treated as unavailable.
    now = datetime.now(timezone.utc)
    this_update = _as_utc(response.this_update_utc)
    next_update = _as_utc(response.next_update_utc)
    if this_update is None or this_update - _CLOCK_SKEW > now:
        return "unavailable"
    if next_update is None or next_update + _CLOCK_SKEW < now:
        return "unavailable"

    # Signature by the issuer or an authorised delegated responder: accept if
    # any authorised key verifies it.
    signer_keys = _responder_keys(response, issuer)
    if not any(_verify_signature(key, response.signature,
                                 response.tbs_response_bytes,
                                 response.signature_hash_algorithm)
               for key in signer_keys):
        return "unavailable"

    status = response.certificate_status
    if status == ocsp.OCSPCertStatus.GOOD:
        return "good"
    if status == ocsp.OCSPCertStatus.REVOKED:
        return "revoked"
    return "unknown"


def check_ocsp(leaf_der: bytes, issuer_der: Optional[bytes], url: str,
               timeout: float) -> str:
    """Query the OCSP responder for ``leaf_der`` and return a validated status.

    ``issuer_der`` must already be a validated issuer of the leaf (see
    ``select_issuer``); this function does not re-derive trust.
    """
    if not issuer_der or not url:
        return "unavailable"
    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
        issuer = x509.load_der_x509_certificate(issuer_der)
        request = (
            ocsp.OCSPRequestBuilder()
            .add_certificate(leaf, issuer, hashes.SHA1())  # SHA-1 is the OCSP CertID norm
            .build()
        )
        body = request.public_bytes(serialization.Encoding.DER)
    except Exception:
        return "unavailable"
    raw = _safe_open(url, timeout, data=body, content_type="application/ocsp-request")
    if raw is None:
        return "unavailable"
    return validate_response(raw, leaf, issuer)


def fetch_issuer(leaf_der: bytes, ca_issuer_urls: list[str], timeout: float) -> Optional[bytes]:
    """Best-effort issuer retrieval via the AIA caIssuers URL (DER or PKCS7).

    Used when the server did not supply the chain (e.g. the TLS stack could not
    expose it). SSRF-guarded like all other fetches, and the returned issuer is
    cryptographically verified to have issued the leaf before it is trusted.
    Returns DER bytes or None.
    """
    for url in ca_issuer_urls:
        raw = _safe_open(url, timeout)
        if raw is None:
            continue
        candidates: list[bytes] = []
        # A bare DER certificate, or a PKCS7 bundle (pick whichever parses).
        try:
            candidates.append(
                x509.load_der_x509_certificate(raw).public_bytes(_DER)
            )
        except Exception:
            try:
                from cryptography.hazmat.primitives.serialization import pkcs7
                candidates = [
                    c.public_bytes(_DER)
                    for c in pkcs7.load_der_pkcs7_certificates(raw)
                ]
            except Exception:
                candidates = []
        issuer = select_issuer(leaf_der, candidates)
        if issuer is not None:
            return issuer
    return None
