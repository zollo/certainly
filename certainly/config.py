"""Application configuration.

All settings can be provided via environment variables (optionally prefixed
with ``CERTAINLY_``) or via a ``.env`` file. This keeps deployment simple:
a single container reads its whole configuration from the environment.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for Certainly.

    Every value has a sensible default so the app runs out of the box, but
    each one can be overridden through the environment or a config file.
    """

    model_config = SettingsConfigDict(
        env_prefix="CERTAINLY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Web / API ---------------------------------------------------------
    host: str = Field(default="0.0.0.0", description="Bind address for the API server.")
    port: int = Field(default=8000, description="Port for the API server.")
    cors_allow_origins: list[str] = Field(
        default_factory=list,
        description=(
            "Cross-origin origins allowed to call the API from a browser. "
            "Empty by default: the bundled UI is same-origin, so no CORS access "
            "is granted unless you explicitly configure it (e.g. '*' or a list). "
            "Keeping this closed avoids turning an unauthenticated deployment "
            "into an open scanning relay driven from a victim's browser."
        ),
    )

    # --- Scan limits -------------------------------------------------------
    max_targets_per_request: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum number of hosts a single scan request may contain.",
    )
    scan_concurrency: int = Field(
        default=10,
        ge=1,
        le=100,
        description="How many hosts a worker analyzes in parallel per job.",
    )
    probe_concurrency: int = Field(
        default=12,
        ge=1,
        le=64,
        description="Parallel TLS probes (protocols/ciphers) per host.",
    )
    connect_timeout: float = Field(
        default=8.0,
        gt=0,
        description="Per-connection socket timeout, in seconds.",
    )
    default_port: int = Field(
        default=443,
        description="Port used when a target does not specify one.",
    )

    # --- Caching -----------------------------------------------------------
    cache_ttl_seconds: int = Field(
        default=24 * 60 * 60,
        ge=0,
        description="How long (seconds) a host result is cached. 0 disables caching.",
    )

    # --- Job queue / storage ----------------------------------------------
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL used for the job queue and result cache.",
    )
    job_result_ttl_seconds: int = Field(
        default=7 * 24 * 60 * 60,
        ge=60,
        description="How long finished job records are retained in Redis.",
    )
    job_timeout_seconds: int = Field(
        default=300,
        ge=30,
        description="Maximum wall-clock time for a single scan job.",
    )
    use_inline_worker: bool = Field(
        default=False,
        description=(
            "Run jobs synchronously in-process instead of on an RQ worker. "
            "Handy for local development and tests without a worker container."
        ),
    )

    @field_validator("cors_allow_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        # Allow a comma-separated string from the environment.
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    """Return a cached :class:`Settings` instance."""
    return Settings()
