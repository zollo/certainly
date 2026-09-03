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

EXPOSE 8000

# Default role: API + web server. Override the command to run the worker.
CMD ["uvicorn", "certainly.main:app", "--host", "0.0.0.0", "--port", "8000"]
