"""Small public FastAPI app: paste/upload a .sol file, see findings, JSON + /health."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from auditor.jsonlog import RequestLogMiddleware, configure_json_logging
from auditor.mode import is_public, public_limits
from auditor.public_demo.limits import Busy, RateLimited, check_rate_limit, client_ip, scan_slot
from auditor.public_demo.scan import scan_source
from auditor.settings import load_settings

log = logging.getLogger("contract_auditor.public")

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
SAMPLES_DIR = Path(__file__).resolve().parents[2] / "samples"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

_SAFE_SAMPLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}\.sol$")

# Prefixes that must 404 in public mode (defense in depth; they are also
# simply not registered).
_BLOCKED_PREFIXES = (
    "/api/monitor", "/monitor", "/api/hunt", "/hunt",
    "/api/discovery", "/discovery", "/api/finrisk", "/finrisk",
    "/api/exploitable", "/exploits",
    "/api/simulate", "/simulate",
    "/benchmark", "/api/benchmark",
    "/api/validate-address",
    "/api/patches", "/api/proposals",
    "/api/opencode",
    "/tools", "/api/tools",
    "/history", "/findings", "/investigate",
    "/jobs", "/api/jobs", "/api/ai-audit",
    "/api/overview", "/api/dashboard", "/api/review-panel",
    "/api/disk-pressure",
)


def _list_samples() -> list[dict[str, str]]:
    if not SAMPLES_DIR.is_dir():
        return []
    items = []
    for path in sorted(SAMPLES_DIR.glob("*.sol")):
        title = path.stem.replace("_", " ")
        first = ""
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("//"):
                first = line.strip("/ ").strip()
                break
        items.append({"id": path.name, "title": title, "blurb": first})
    return items


def _read_sample(name: str) -> Optional[str]:
    if not _SAFE_SAMPLE.match(name):
        return None
    path = (SAMPLES_DIR / name).resolve()
    if not path.is_file() or path.parent != SAMPLES_DIR.resolve():
        return None
    return path.read_text(encoding="utf-8")


def _disabled() -> JSONResponse:
    return JSONResponse(
        {"error": "this route is disabled in public demo mode"},
        status_code=404,
    )


def _extract_source(source: Optional[str], upload: Optional[UploadFile],
                    max_bytes: int) -> tuple[str, str]:
    if upload is not None and upload.filename:
        filename = Path(upload.filename).name
        if not filename.lower().endswith(".sol"):
            raise ValueError("only a single .sol file is accepted")
        # Read at most max_bytes + 1 to detect overflow without slurping huge bodies.
        data = upload.file.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"file exceeds the {max_bytes} byte size cap")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("file is not valid UTF-8") from exc
        return text, filename
    text = source or ""
    if not str(text).strip():
        raise ValueError("paste Solidity source or upload a .sol file")
    encoded = text.encode("utf-8")
    if len(encoded) > max_bytes:
        raise ValueError(f"source exceeds the {max_bytes} byte size cap")
    return text, "paste.sol"


def create_public_app() -> FastAPI:
    configure_json_logging()
    limits = public_limits()
    app = FastAPI(
        title="Contract Auditor — public demo",
        description="Paste or upload a Solidity file for a local static scan. "
                    "No chain access, no path access, no Keychain.",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.add_middleware(RequestLogMiddleware)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        settings = load_settings()
        from auditor.llm import configured_provider
        return {
            "status": "healthy",
            "mode": "public" if is_public() else "local",
            "provider": configured_provider(settings.get("model.provider")),
        }

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "samples": _list_samples(),
                "max_bytes": limits["max_upload_bytes"],
                "rate_limit": limits["rate_limit_scans_per_hour"],
            },
        )

    @app.get("/api/samples")
    async def api_samples() -> dict[str, Any]:
        return {"samples": _list_samples()}

    @app.get("/api/samples/{name}")
    async def api_sample(name: str) -> Any:
        text = _read_sample(name)
        if text is None:
            return JSONResponse({"error": "unknown sample"}, status_code=404)
        return {"id": name, "source": text}

    @app.post("/api/scan")
    async def api_scan(request: Request) -> Any:
        content_type = (request.headers.get("content-type") or "").lower()
        source: Optional[str] = None
        upload: Optional[UploadFile] = None
        filename_hint = "paste.sol"
        if "application/json" in content_type:
            try:
                body = await request.json()
            except Exception:
                body = {}
            if not isinstance(body, dict):
                return JSONResponse({"error": "JSON body must be an object"}, status_code=400)
            if body.get("path") or body.get("address") or body.get("etherscan"):
                return JSONResponse(
                    {"error": "local paths and chain addresses are disabled in public mode"},
                    status_code=400,
                )
            source = body.get("source") or body.get("solidity")
            filename_hint = body.get("filename") or "paste.sol"
        else:
            form = await request.form()
            if form.get("path") or form.get("address") or form.get("etherscan"):
                return JSONResponse(
                    {"error": "local paths and chain addresses are disabled in public mode"},
                    status_code=400,
                )
            maybe_source = form.get("source") or form.get("solidity")
            source = maybe_source if isinstance(maybe_source, str) else None
            maybe_file = form.get("file")
            if isinstance(maybe_file, UploadFile):
                upload = maybe_file
            filename_hint = str(form.get("filename") or "paste.sol")

        try:
            text, filename = _extract_source(source, upload, limits["max_upload_bytes"])
            if upload is None and str(filename_hint).endswith(".sol"):
                filename = Path(str(filename_hint)).name
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        ip = client_ip(request)
        try:
            check_rate_limit(ip, limits["rate_limit_scans_per_hour"])
        except RateLimited as exc:
            return JSONResponse(
                {"error": "rate limit exceeded", "retry_after_s": exc.retry_after_s},
                status_code=429,
                headers={"Retry-After": str(exc.retry_after_s)},
            )

        try:
            with scan_slot():
                result = scan_source(
                    text,
                    filename=filename,
                    timeout=float(limits["scan_timeout_seconds"]),
                    allow_install=False,
                )
        except Busy:
            return JSONResponse(
                {"error": "too many scans in progress; try again shortly"},
                status_code=429,
            )

        request.state.scan_outcome = result.get("status")
        status_code = 200 if result.get("status") == "completed" else 200
        # Compile/tool failures are still 200 with status in the body so the
        # UI can render them; they are not silently dropped.
        return JSONResponse({k: v for k, v in result.items()}, status_code=status_code)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def blocked(path: str) -> JSONResponse:
        # Anything not registered above is unavailable in public mode.
        return _disabled()

    return app


def run_public_dashboard(host: str = "0.0.0.0", port: int = 8080, reload: bool = False) -> None:
    import uvicorn

    configure_json_logging()
    log.info("starting public demo on http://%s:%s", host, port)
    uvicorn.run(
        "auditor.public_demo.app:create_public_app",
        host=host,
        port=port,
        reload=reload,
        factory=True,
        log_level="info",
    )
