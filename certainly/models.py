"""Pydantic models describing API requests, responses, and scan results."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    """Lifecycle states for a scan job."""

    QUEUED = "queued"
    RUNNING = "running"
    FINISHED = "finished"
    FAILED = "failed"


class ScanRequest(BaseModel):
    """Incoming request to scan one or more targets."""

    targets: list[str] = Field(
        ...,
        min_length=1,
        description="Hostnames or URLs to analyze, e.g. 'example.com' or 'https://example.com:443'.",
        examples=[["example.com", "badssl.com", "https://github.com"]],
    )
    bypass_cache: bool = Field(
        default=False,
        description="Force a fresh scan even if a cached result exists.",
    )


class SubmitResponse(BaseModel):
    """Response returned immediately after a scan is queued."""

    job_id: str
    status: JobStatus
    targets: list[str]
    status_url: str
    result_url: str


class ProtocolResult(BaseModel):
    """Support status for a single TLS/SSL protocol version."""

    name: str
    supported: bool
    secure: bool = Field(description="Whether the protocol is considered secure.")


class CipherResult(BaseModel):
    """A cipher suite offered by the server."""

    name: str
    protocol: str
    bits: Optional[int] = None
    forward_secrecy: bool = False
    strong: bool = True
    aead: bool = False


class CertificateInfo(BaseModel):
    """Parsed details of an X.509 certificate."""

    subject: str
    subject_alt_names: list[str] = Field(default_factory=list)
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    days_until_expiry: int
    is_expired: bool
    is_not_yet_valid: bool
    is_self_signed: bool
    signature_algorithm: str
    key_type: str
    key_bits: Optional[int] = None
    sha256_fingerprint: str
    version: str
    hostname_matches: bool
    weak_signature: bool = Field(
        default=False, description="True for MD5/SHA-1 based signatures."
    )


class Finding(BaseModel):
    """A single observation that affects the security posture / score."""

    severity: str = Field(description="one of: good, info, low, medium, high, critical")
    title: str
    detail: str


class ScoreBreakdown(BaseModel):
    """Component scores that combine into the overall grade."""

    protocol_support: int
    key_exchange: int
    cipher_strength: int
    certificate: int


class HostResult(BaseModel):
    """Full analysis result for one host."""

    target: str
    hostname: str
    port: int
    ip_address: Optional[str] = None
    reachable: bool
    error: Optional[str] = None

    score: int = Field(default=0, ge=0, le=100)
    grade: str = "F"

    breakdown: Optional[ScoreBreakdown] = None
    certificate: Optional[CertificateInfo] = None
    certificate_chain: list[CertificateInfo] = Field(default_factory=list)
    protocols: list[ProtocolResult] = Field(default_factory=list)
    ciphers: list[CipherResult] = Field(default_factory=list)

    forward_secrecy: bool = False
    hsts: bool = False
    hsts_max_age: Optional[int] = None
    supports_tls13: bool = False

    findings: list[Finding] = Field(default_factory=list)
    duration_seconds: float = 0.0
    scanned_at: Optional[datetime] = None
    from_cache: bool = False


class JobResult(BaseModel):
    """The complete result payload for a scan job."""

    job_id: str
    status: JobStatus
    submitted_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    targets: list[str]
    results: list[HostResult] = Field(default_factory=list)
    error: Optional[str] = None
