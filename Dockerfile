# Certainly — SSL/TLS analyzer
# A single image serves both the API/web process and the worker process;
# the command chosen at runtime (see docker-compose.yml) decides the role.
FROM python:3.13-slim

# System deps: OpenSSL is used via Python's ssl module for legacy protocol
# probing. build-essential is only needed if a wheel isn't available.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir --no-deps -e .

# Build metadata, injected by the release pipeline and surfaced in the UI
# footer. Declared after the dependency layers so a new commit/date doesn't
# bust the pip cache. Left empty for local/PR builds, where the app falls back
# to the packaged version.
ARG CERTAINLY_VERSION=""
ARG CERTAINLY_GIT_COMMIT=""
ARG CERTAINLY_BUILD_DATE=""
ENV CERTAINLY_VERSION=$CERTAINLY_VERSION \
    CERTAINLY_GIT_COMMIT=$CERTAINLY_GIT_COMMIT \
    CERTAINLY_BUILD_DATE=$CERTAINLY_BUILD_DATE

EXPOSE 8000

# Default role: API + web server. Override the command to run the worker.
CMD ["uvicorn", "certainly.main:app", "--host", "0.0.0.0", "--port", "8000"]
