# Certainly Helm chart

Deploy [Certainly](https://github.com/zollo/certainly), an open-source SSL/TLS
analyzer, to Kubernetes.

The chart deploys three workloads, mirroring the Docker Compose topology:

- **api** — the FastAPI app serving the web UI and REST API (`uvicorn`).
- **worker** — one or more RQ workers executing scan jobs.
- **redis** — job queue and result cache (bundled by default; use an external
  Redis in production by setting `redis.enabled=false`).

## Prerequisites

- Kubernetes 1.23+ (the chart uses `autoscaling/v2` and `networking.k8s.io/v1`).
- Helm 3.x.

## Installing

```sh
# From a checkout of the repo:
helm install certainly ./charts/certainly

# Override values:
helm install certainly ./charts/certainly \
  --set image.tag=1.0.0 \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=certainly.example.com
```

By default the chart deploys the API, a worker, and a bundled Redis with a 1Gi
persistent volume. The API is exposed as a `ClusterIP` Service; enable the
Ingress or change `service.type` to expose it.

## Upgrading / uninstalling

```sh
helm upgrade certainly ./charts/certainly -f my-values.yaml
helm uninstall certainly
```

> The bundled Redis PVC is not removed by `helm uninstall`. Delete it manually
> if you no longer need the cached data.

## Configuration

All application settings map to `CERTAINLY_*` environment variables (see the
repo's `.env.example`). Set non-secret values under `config`, and secret values
(e.g. a Redis URL containing credentials) under `secretEnv` or via
`existingSecret`.

| Key | Default | Description |
| --- | --- | --- |
| `image.repository` | `ghcr.io/zollo/certainly` | Image repository (shared by API and worker). |
| `image.tag` | `""` (chart `appVersion`) | Image tag. |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy. |
| `imagePullSecrets` | `[]` | Secrets for pulling from a private registry. |
| `config.*` | see `values.yaml` | Non-secret `CERTAINLY_*` settings. |
| `extraEnv` | `{}` | Extra plain env vars (added to the ConfigMap). |
| `secretEnv` | `{}` | Sensitive env vars (rendered into a Secret). |
| `existingSecret` | `""` | Use a pre-existing Secret instead of `secretEnv`. |
| `api.replicaCount` | `1` | API replicas (ignored when autoscaling). |
| `api.resources` | requests 100m/128Mi, limits 1/512Mi | API resources. |
| `api.livenessProbe` / `api.readinessProbe` | `/api/health` | HTTP probes. |
| `api.autoscaling.enabled` | `false` | Enable an HPA for the API. |
| `worker.enabled` | `true` | Deploy the background worker. |
| `worker.replicaCount` | `1` | Worker replicas (ignored when autoscaling). |
| `worker.autoscaling.enabled` | `false` | Enable an HPA for the worker. |
| `service.type` | `ClusterIP` | API Service type. |
| `service.port` | `80` | API Service port. |
| `ingress.enabled` | `false` | Create an Ingress for the API. |
| `ingress.className` | `""` | IngressClass name. |
| `ingress.hosts` | `certainly.local` | Ingress host/path rules. |
| `ingress.tls` | `[]` | Ingress TLS config. |
| `redis.enabled` | `true` | Deploy a bundled Redis. |
| `redis.persistence.enabled` | `true` | Persist Redis data via a PVC. |
| `redis.persistence.size` | `1Gi` | PVC size. |
| `externalRedis.url` | `""` | Redis URL when `redis.enabled=false`. |

### Using an external Redis

```sh
helm install certainly ./charts/certainly \
  --set redis.enabled=false \
  --set externalRedis.url=redis://my-redis:6379/0
```

If the URL contains credentials, supply it as a secret instead:

```sh
helm install certainly ./charts/certainly \
  --set redis.enabled=false \
  --set secretEnv.CERTAINLY_REDIS_URL=redis://:password@my-redis:6379/0
```

### Running without a separate worker

To run scan jobs in-process (no worker Deployment):

```sh
helm install certainly ./charts/certainly \
  --set worker.enabled=false \
  --set config.useInlineWorker=true
```
