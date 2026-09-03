"""FastAPI application exposing the Certainly API and web UI."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .jobs import get_job, submit_scan
from .models import JobStatus, ScanRequest, SubmitResponse

STATIC_DIR = Path(__file__).parent / "web" / "static"

app = FastAPI(
    title="Certainly",
    description="An open-source SSL/TLS analyzer — inspect certificates, "
                "protocols, and cipher suites, and score security posture.",
    version="1.0.0",
)

settings = get_settings()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", tags=["meta"])
def health() -> dict:
    """Simple liveness probe."""
    return {"status": "ok", "service": "certainly"}


@app.get("/api/config", tags=["meta"])
def config() -> dict:
    """Expose non-sensitive configuration the UI needs (e.g. limits)."""
    return {
        "max_targets_per_request": settings.max_targets_per_request,
        "cache_ttl_seconds": settings.cache_ttl_seconds,
        "default_port": settings.default_port,
    }


@app.post("/api/scan", response_model=SubmitResponse, tags=["scan"])
def create_scan(request: ScanRequest, http_request: Request) -> SubmitResponse:
    """Queue a scan for one or more targets and return a job id."""
    targets = [t.strip() for t in request.targets if t and t.strip()]
    if not targets:
        raise HTTPException(status_code=422, detail="No valid targets provided.")

    limit = settings.max_targets_per_request
    if len(targets) > limit:
        raise HTTPException(
            status_code=422,
            detail=f"Too many targets: {len(targets)} provided, maximum is {limit}.",
        )

    job = submit_scan(targets, bypass_cache=request.bypass_cache, settings=settings)

    base = str(http_request.base_url).rstrip("/")
    return SubmitResponse(
        job_id=job.job_id,
        status=job.status,
        targets=job.targets,
        status_url=f"{base}/api/jobs/{job.job_id}/status",
        result_url=f"{base}/api/jobs/{job.job_id}",
    )


@app.get("/api/jobs/{job_id}", tags=["scan"])
def read_job(job_id: str):
    """Return the full job record, including results when finished."""
    job = get_job(job_id, settings=settings)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found.")
    return job


@app.get("/api/jobs/{job_id}/status", tags=["scan"])
def read_job_status(job_id: str) -> dict:
    """Return a lightweight status view for polling."""
    job = get_job(job_id, settings=settings)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found.")
    total = len(job.targets)
    completed = len(job.results) if job.status == JobStatus.FINISHED else 0
    return {
        "job_id": job.job_id,
        "status": job.status,
        "total": total,
        "completed": completed,
        "submitted_at": job.submitted_at,
        "finished_at": job.finished_at,
    }


# --------------------------------------------------------------------------- #
# Static web UI
# --------------------------------------------------------------------------- #
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(str(STATIC_DIR / "index.html"))
