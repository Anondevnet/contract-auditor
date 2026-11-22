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

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

CMD ["python3", "audit.py", "dashboard", "--host", "0.0.0.0", "--port", "8080"]
