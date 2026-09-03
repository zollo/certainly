"""Job queue and job lifecycle management.

A submitted scan becomes a *job* with a unique id. Jobs are executed either:

* on an RQ worker (default, production) — the API enqueues work and returns
  immediately with a job id; or
* inline / synchronously (``CERTAINLY_USE_INLINE_WORKER=true``) — handy for
  local development and tests without a separate worker process.

Job records (status + results) are persisted in Redis as JSON so any API
process can read them. When Redis is unavailable (inline dev mode) an
in-process dictionary is used instead.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from .cache import ResultCache
from .config import Settings, get_settings
from .models import JobResult, JobStatus
from .scanner import analyze_targets, parse_target

_JOB_PREFIX = "certainly:job:"

# In-process fallback store (used when Redis is not configured/available).
_MEMORY_JOBS: dict[str, str] = {}


class QueueUnavailableError(RuntimeError):
    """Raised when a scan cannot be queued because Redis is unreachable.

    This is deliberately surfaced (as HTTP 503) rather than silently running
    the scan inline: doing heavy synchronous work inside the API process would
    risk request timeouts and tie up web workers. Set
    ``CERTAINLY_USE_INLINE_WORKER=true`` to run scans in-process on purpose.
    """


# --------------------------------------------------------------------------- #
# Redis / queue plumbing
# --------------------------------------------------------------------------- #
def get_redis(settings: Settings):
    """Return a Redis client, or ``None`` if it cannot be reached."""
    try:
        import redis  # imported lazily so the package works without redis installed
    except ImportError:  # pragma: no cover
        return None
    try:
        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        client.ping()
        return client
    except Exception:
        return None


def get_queue(settings: Settings, redis_client):
    """Return an RQ queue bound to ``redis_client`` (bytes responses)."""
    from redis import Redis
    from rq import Queue

    # RQ needs a connection that returns bytes, not decoded strings.
    conn = Redis.from_url(settings.redis_url)
    return Queue("certainly", connection=conn,
                 default_timeout=settings.job_timeout_seconds)


# --------------------------------------------------------------------------- #
# Job persistence
# --------------------------------------------------------------------------- #
class JobStore:
    def __init__(self, redis_client, ttl_seconds: int):
        self._redis = redis_client
        self._ttl = ttl_seconds

    @staticmethod
    def _key(job_id: str) -> str:
        return f"{_JOB_PREFIX}{job_id}"

    def save(self, job: JobResult) -> None:
        payload = job.model_dump_json()
        if self._redis is not None:
            try:
                self._redis.set(self._key(job.job_id), payload, ex=self._ttl)
                return
            except Exception:
                pass
        _MEMORY_JOBS[job.job_id] = payload

    def get(self, job_id: str) -> Optional[JobResult]:
        payload = None
        if self._redis is not None:
            try:
                payload = self._redis.get(self._key(job_id))
            except Exception:
                payload = None
        if payload is None:
            payload = _MEMORY_JOBS.get(job_id)
        if payload is None:
            return None
        try:
            return JobResult.model_validate_json(payload)
        except Exception:
            return None


def _store_for(settings: Settings) -> JobStore:
    return JobStore(get_redis(settings), settings.job_result_ttl_seconds)


# --------------------------------------------------------------------------- #
# Public API used by the web layer
# --------------------------------------------------------------------------- #
def submit_scan(targets: list[str], bypass_cache: bool,
                settings: Optional[Settings] = None) -> JobResult:
    """Create a job for ``targets`` and enqueue (or run) it.

    Returns the initial :class:`JobResult` (status ``queued``). The heavy work
    happens later on a worker unless inline mode is enabled.
    """
    settings = settings or get_settings()
    store = _store_for(settings)

    job = JobResult(
        job_id=uuid.uuid4().hex,
        status=JobStatus.QUEUED,
        submitted_at=datetime.now(timezone.utc),
        targets=targets,
    )
    store.save(job)

    if settings.use_inline_worker:
        execute_job(job.job_id, targets, bypass_cache)
        refreshed = store.get(job.job_id)
        return refreshed or job

    redis_client = get_redis(settings)
    if redis_client is None:
        # Fail fast rather than silently running a heavy scan synchronously in
        # the API process. Inline execution is opt-in via USE_INLINE_WORKER.
        raise QueueUnavailableError(
            "Job queue is unavailable (cannot reach Redis). Ensure Redis is "
            "running, or set CERTAINLY_USE_INLINE_WORKER=true to run scans "
            "in-process."
        )

    queue = get_queue(settings, redis_client)
    queue.enqueue(
        "certainly.jobs.execute_job",
        job.job_id,
        targets,
        bypass_cache,
        job_timeout=settings.job_timeout_seconds,
    )
    return job


def get_job(job_id: str, settings: Optional[Settings] = None) -> Optional[JobResult]:
    settings = settings or get_settings()
    return _store_for(settings).get(job_id)


def execute_job(job_id: str, targets: list[str], bypass_cache: bool) -> None:
    """Run a scan job. This is the function executed on the RQ worker.

    It reconstructs its dependencies from configuration so it is safe to call
    in a fresh worker process.
    """
    settings = get_settings()
    store = _store_for(settings)
    cache = ResultCache(get_redis(settings), settings.cache_ttl_seconds)

    job = store.get(job_id) or JobResult(
        job_id=job_id, status=JobStatus.QUEUED,
        submitted_at=datetime.now(timezone.utc), targets=targets,
    )
    job.status = JobStatus.RUNNING
    job.started_at = datetime.now(timezone.utc)
    store.save(job)

    try:
        results = _scan_with_cache(targets, bypass_cache, settings, cache)
        job.results = results
        job.status = JobStatus.FINISHED
    except Exception as exc:  # pragma: no cover - defensive
        job.status = JobStatus.FAILED
        job.error = str(exc)
    finally:
        job.finished_at = datetime.now(timezone.utc)
        store.save(job)


def _scan_with_cache(targets: list[str], bypass_cache: bool,
                     settings: Settings, cache: ResultCache):
    """Return results for ``targets``, using the cache where possible."""
    results_by_index: dict[int, object] = {}
    to_scan: list[tuple[int, str]] = []

    for index, raw in enumerate(targets):
        if bypass_cache or not cache.enabled:
            to_scan.append((index, raw))
            continue
        try:
            parsed = parse_target(raw, settings.default_port)
        except ValueError:
            to_scan.append((index, raw))
            continue
        cached = cache.get(parsed.hostname, parsed.port)
        if cached is not None:
            results_by_index[index] = cached
        else:
            to_scan.append((index, raw))

    if to_scan:
        scanned = analyze_targets(
            [raw for _i, raw in to_scan],
            default_port=settings.default_port,
            timeout=settings.connect_timeout,
            concurrency=settings.scan_concurrency,
            probe_workers=settings.probe_concurrency,
        )
        for (index, _raw), result in zip(to_scan, scanned):
            if result.reachable:
                cache.set(result)
            results_by_index[index] = result

    return [results_by_index[i] for i in range(len(targets))]
