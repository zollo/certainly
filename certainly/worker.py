"""RQ worker entrypoint.

Run with ``python -m certainly.worker``. The worker consumes scan jobs from
the ``certainly`` queue and executes them via :func:`certainly.jobs.execute_job`.
"""
from __future__ import annotations

import sys

from redis import Redis
from rq import Queue, Worker

from .config import get_settings


def main() -> int:
    settings = get_settings()
    connection = Redis.from_url(settings.redis_url)
    queue = Queue("certainly", connection=connection,
                  default_timeout=settings.job_timeout_seconds)
    worker = Worker([queue], connection=connection)
    print(f"[certainly] worker listening on '{queue.name}' via {settings.redis_url}")
    worker.work(with_scheduler=True)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
