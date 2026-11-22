"""Structured JSON logging. Never log source code, secrets, or raw uploads."""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

log = logging.getLogger("contract_auditor")

# Keys that must never be copied into a log record.
_REDACT_KEYS = {
    "source", "code", "solidity", "content", "file", "upload", "body",
    "api_key", "authorization", "password", "secret", "token", "raw",
    "excerpt", "AUDITOR_LLM_API_KEY", "ETHERSCAN_API_KEY", "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
}


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


def safe_extra(data: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in (data or {}).items():
        if key.lower() in {k.lower() for k in _REDACT_KEYS}:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            out[key] = value
        else:
            out[key] = type(value).__name__
    return out


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in (
            "request_id", "route", "method", "status", "duration_ms",
            "scan_outcome", "client_ip", "solc_version", "n_findings",
            "error_type",
        ):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, default=str, ensure_ascii=False)


def configure_json_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger("contract_auditor")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False


class RequestLogMiddleware(BaseHTTPMiddleware):
    """Attach a request id and log method, route, status, duration. No bodies."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("x-request-id") or new_request_id()
        request.state.request_id = request_id
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            duration_ms = round((time.perf_counter() - start) * 1000, 1)
            client = request.client.host if request.client else "unknown"
            outcome = getattr(request.state, "scan_outcome", None)
            log.info(
                "request",
                extra={
                    "request_id": request_id,
                    "route": request.url.path,
                    "method": request.method,
                    "status": status,
                    "duration_ms": duration_ms,
                    "client_ip": client,
                    "scan_outcome": outcome,
                },
            )
