# Deploying Certainly as a TrueNAS SCALE app

TrueNAS SCALE **Electric Eel (24.10)** and later run apps on Docker, and you
can deploy any Docker Compose stack as a **Custom App**. Certainly is published
as a container image on GHCR, so no building is required on the NAS.

> Requires TrueNAS SCALE 24.10 or newer (the Docker-based Apps engine).

## 1. Create a dataset for persistent data

Redis stores Certainly's cached results and job records. Give it a dataset so
the data lives on your pool and is included in snapshots:

1. Go to **Datasets**, select your pool, and click **Add Dataset**.
2. Name it e.g. `apps/certainly/redis` (any path is fine).
3. Note its mountpoint — it will be something like `/mnt/tank/apps/certainly/redis`
   (with your pool name in place of `tank`).

## 2. Install the Custom App from YAML

1. Go to **Apps**.
2. Click the **three-dot menu** next to **Custom App** and choose
   **Install via YAML**.
3. Enter an **Application Name** (e.g. `certainly`).
4. Paste the contents of [`docker-compose.yaml`](./docker-compose.yaml) into the
   YAML editor.
5. Edit the three marked values:
   - **Redis volume path** — replace `/mnt/tank/apps/certainly/redis` with the
     dataset mountpoint from step 1.
   - **Web port** — change `30080` if that host port is taken. (Avoid 80/443,
     which the TrueNAS UI uses.)
   - **Image tag** *(optional)* — pin a version, e.g.
     `ghcr.io/zollo/certainly:1.0.0`, instead of `:latest`.
6. Click **Save**. TrueNAS pulls the images and starts the three services
   (`api`, `worker`, `redis`).

Once the app is **Running**, open `http://<truenas-ip>:30080` (or the port you
chose) for the web UI. The API lives under the same address at `/api`, with
interactive docs at `/docs`.

## 3. Configuration

Set any [`CERTAINLY_*` option](../../.env.example) directly in the `environment:`
block of the `api` (and `worker`, where relevant) service. Common ones:

| Variable                            | Purpose                                  |
| ----------------------------------- | ---------------------------------------- |
| `CERTAINLY_MAX_TARGETS_PER_REQUEST` | Max targets per scan (default 10).       |
| `CERTAINLY_CACHE_TTL_SECONDS`       | Result cache lifetime (default 24h).     |
| `CERTAINLY_SCAN_CONCURRENCY`        | Hosts scanned in parallel per job.       |

`CERTAINLY_REDIS_URL` is already wired to the bundled `redis` service — leave it
as is.

## 4. Updating

- **Pinned tag:** edit the app's YAML, bump the image tag, and Save.
- **`:latest`:** use the app's **Update**/redeploy action, or edit and re-Save,
  to pull the newest image.

Because Redis data is on your dataset, cached results and job history survive
updates and restarts.

## Notes

- **Scaling workers:** the Custom App runs a single `worker`. To scan more hosts
  concurrently, raise `CERTAINLY_SCAN_CONCURRENCY` on the existing services, or
  add another worker service (e.g. `worker2`) with the same definition.
- **Named volume alternative:** if you'd rather not manage a dataset path,
  replace the `redis` bind mount with a named volume — add a top-level
  `volumes: { certainly-redis: {} }` and use `certainly-redis:/data`. TrueNAS
  stores it under the apps pool automatically.
- **Reverse proxy / TLS:** to expose Certainly over HTTPS, front it with your
  existing reverse proxy (e.g. Traefik or Nginx Proxy Manager) pointing at the
  chosen host port.
