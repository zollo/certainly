# 🔒 Certainly

**Certainly** is a free and open-source SSL/TLS analyzer — a self-hostable
alternative to Qualys SSL Labs. Point it at one or more servers and it inspects
their certificates, supported protocols, and cipher suites, then scores each
one from **0–100** based on its SSL/TLS security posture.

- 🌐 **Web UI** — analyze up to *N* targets at once (default 10, configurable).
- 🔌 **REST API** — everything the UI shows is available over an unauthenticated
  API. Submit a scan, get a **job ID**, poll for status, retrieve results.
- ⚡ **Parallel** — hosts are scanned concurrently, and each host's protocol and
  cipher probes run in parallel.
- 🧮 **Scored** — a weighted score (protocol support, key exchange, cipher
  strength, certificate) plus a convenience letter grade (A+ … F).
- 🗃️ **Cached** — results are cached (default 24h, configurable) in Redis.
- 📦 **Container-native** — `docker compose up` and you're running. All config
  via environment variables or a `.env` file.

---

## Quick start (Docker)

```bash
git clone https://github.com/zollo/certainly.git
cd certainly
docker compose up --build
```

Then open <http://localhost:8000>.

To customize configuration, copy `.env.example` to `.env` and edit it, or set
`CERTAINLY_*` environment variables directly. Scale scanning throughput by
adding workers:

```bash
docker compose up --scale worker=3
```

### Using the pre-built image

Every push to `main` publishes a multi-arch image (linux/amd64 + arm64) to the
GitHub Container Registry via CI. Pull it directly instead of building:

```bash
docker pull ghcr.io/zollo/certainly:latest
```

Tags include `latest` (main), `main`, a short commit SHA, and — for release
tags like `v1.2.3` — the matching `1.2.3` and `1.2` versions. Point the
`image:` field of both the `api` and `worker` services at the published image
to run without a local build.

## Quick start (local, no Docker)

Certainly needs Redis for the job queue and cache. For quick local development
you can skip both the worker and Redis by enabling the **inline worker**, which
runs scans synchronously inside the API process:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .

# Inline mode: no Redis or worker required.
CERTAINLY_USE_INLINE_WORKER=true uvicorn certainly.main:app --reload
```

For the full setup (recommended), run Redis and a worker:

```bash
# terminal 1
redis-server

# terminal 2 — worker
python -m certainly.worker

# terminal 3 — API + UI
uvicorn certainly.main:app --reload
```

---

## API

The web UI is built entirely on top of this API. No authentication is required.

### `POST /api/scan`

Queue a scan. Returns a job ID immediately.

```bash
curl -s -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"targets": ["example.com", "https://github.com", "badssl.com"]}'
```

```json
{
  "job_id": "a1b2c3…",
  "status": "queued",
  "targets": ["example.com", "https://github.com", "badssl.com"],
  "status_url": "http://localhost:8000/api/jobs/a1b2c3…/status",
  "result_url": "http://localhost:8000/api/jobs/a1b2c3…"
}
```

Request body:

| Field          | Type       | Default | Description                                    |
| -------------- | ---------- | ------- | ---------------------------------------------- |
| `targets`      | `string[]` | —       | Hostnames or URLs (`example.com`, `host:8443`, `https://…`). |
| `bypass_cache` | `boolean`  | `false` | Force a fresh scan, ignoring cached results.   |

### `GET /api/jobs/{job_id}/status`

Lightweight status for polling:

```json
{ "job_id": "a1b2c3…", "status": "running", "total": 3, "completed": 0 }
```

`status` is one of `queued`, `running`, `finished`, `failed`.

### `GET /api/jobs/{job_id}`

The full job record. When `status` is `finished`, `results` contains one entry
per target with the score, grade, certificate details, protocols, ciphers, and
findings. See the interactive docs at **`/docs`** for the complete schema.

### `GET /api/config`

Returns UI-relevant limits (`max_targets_per_request`, `cache_ttl_seconds`,
`default_port`).

### `GET /api/health`

Liveness probe.

---

## Scoring

Each host gets a **0–100** score composed of four weighted components,
following a methodology inspired by the [SSL Labs rating guide][ssllabs]:

| Component          | Weight | Basis                                             |
| ------------------ | ------ | ------------------------------------------------- |
| Protocol support   | 30%    | Best/worst negotiated TLS version                 |
| Key exchange       | 30%    | Certificate key strength + forward secrecy        |
| Cipher strength    | 40%    | Strongest/weakest offered cipher                  |
| Certificate        | gate   | Validity, trust, hostname match, signature        |

A series of **caps** then lower the score for materially weakening conditions —
obsolete protocols (SSLv3, TLS 1.0/1.1), weak or broken ciphers (RC4, 3DES,
NULL, EXPORT), missing forward secrecy, or certificate problems. Certificate
issues (expired, self-signed, hostname mismatch) are a hard gate that force a
failing grade. HSTS is required to reach the top grade (A+).

The numeric score maps to a letter grade for at-a-glance reading:

`A+` ≥ 95 · `A` ≥ 80 · `B` ≥ 65 · `C` ≥ 50 · `D` ≥ 35 · `E` ≥ 20 · `F` < 20

[ssllabs]: https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide

---

## Configuration

All settings are read from the environment (prefix `CERTAINLY_`) or a `.env`
file. See [`.env.example`](.env.example) for the full list. The most common:

| Variable                             | Default                    | Description                                  |
| ------------------------------------ | -------------------------- | -------------------------------------------- |
| `CERTAINLY_MAX_TARGETS_PER_REQUEST`  | `10`                       | Max targets per scan request.                |
| `CERTAINLY_CACHE_TTL_SECONDS`        | `86400` (24h)              | How long results are cached (0 disables).    |
| `CERTAINLY_SCAN_CONCURRENCY`         | `10`                       | Hosts scanned in parallel per job.           |
| `CERTAINLY_PROBE_CONCURRENCY`        | `12`                       | Parallel probes per host.                    |
| `CERTAINLY_CONNECT_TIMEOUT`          | `8`                        | Socket timeout (seconds).                    |
| `CERTAINLY_REDIS_URL`                | `redis://localhost:6379/0` | Redis for queue + cache.                     |
| `CERTAINLY_USE_INLINE_WORKER`        | `false`                    | Run jobs in-process (dev only).              |

---

## Architecture

```
          ┌──────────────┐   POST /api/scan    ┌──────────────┐
 Browser  │   Web UI     │ ──────────────────▶ │  FastAPI     │
 / client │ (static JS)  │ ◀────────────────── │  API         │
          └──────────────┘   job_id + polling  └──────┬───────┘
                                                       │ enqueue
                                                       ▼
                                                 ┌───────────┐
                                                 │   Redis   │  queue + cache
                                                 └─────┬─────┘
                                                       │ dequeue
                                                       ▼
                                                 ┌───────────┐  parallel per-host
                                                 │  Worker   │  + per-probe scans
                                                 └───────────┘
```

- **`certainly/scanner/`** — the analysis engine: protocol probing (`tls.py`),
  certificate parsing (`certificate.py`), HSTS checks (`http_checks.py`), and
  scoring (`scoring.py`), orchestrated by `analyzer.py`.
- **`certainly/jobs.py`** — job lifecycle, queueing, and caching.
- **`certainly/main.py`** — FastAPI app (API + static UI).
- **`certainly/worker.py`** — RQ worker entrypoint.

---

## Running the tests

```bash
pip install -e ".[dev]"
pytest
```

The test suite runs fully offline (scoring, target parsing, cipher
classification, and the API in inline mode) — no network access required.

---

## License

[MIT](LICENSE). Scores are informational and provided without warranty.
