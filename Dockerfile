# PhishLens — self-contained image.
# Bundles the native zbar library (for QR decoding) and all Python deps, so a
# teammate needs only Docker + their own API keys in a .env file. No secrets are
# ever copied in (see .dockerignore); keys are injected at run time.

FROM python:3.11-slim AS base

# --- system libraries ------------------------------------------------------
# libzbar0 is the native dependency pyzbar needs to decode QR codes.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libzbar0 \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CACHE_PATH=/data/cache.db

WORKDIR /app

# --- python deps (cached layer) -------------------------------------------
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# --- application code ------------------------------------------------------
COPY app/ ./app/
COPY analyze.py ./analyze.py
COPY eval/ ./eval/
COPY tests/ ./tests/

# --- non-root user + writable cache volume ---------------------------------
RUN useradd --create-home --uid 10001 phishlens \
    && mkdir -p /data \
    && chown -R phishlens:phishlens /app /data
USER phishlens

VOLUME ["/data"]
EXPOSE 8000

# Simple container healthcheck hits the /health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)" || exit 1

CMD ["uvicorn", "app.web.main:app", "--host", "0.0.0.0", "--port", "8000"]
