# Public-demo image. Slither + solc-select only; Foundry is not required
# for the paste/upload path and is intentionally omitted.
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1     AUDITOR_MODE=public     AUDITOR_LLM_PROVIDER=none     AUDITOR_PUBLIC_DATA_DIR=/data     PATH="/home/auditor/.local/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin auditor \
    && mkdir -p /app /data \
    && chown -R auditor:auditor /app /data

WORKDIR /app

COPY --chown=auditor:auditor requirements.txt /app/requirements.txt

USER auditor

RUN pip install --user --no-cache-dir -r requirements.txt \
        slither-analyzer==0.11.2 solc-select==1.2.0 \
    && solc-select install 0.4.26 0.5.17 0.6.12 0.7.6 0.8.20 0.8.26 \
    && solc-select use 0.8.26 --always-install

COPY --chown=auditor:auditor . /app
COPY --chown=auditor:auditor --chmod=755 docker-entrypoint.sh /app/docker-entrypoint.sh

EXPOSE 8080

# Healthcheck uses 8080, the image default. Render sets PORT; the entrypoint honors it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${PORT:-8080}/health || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
