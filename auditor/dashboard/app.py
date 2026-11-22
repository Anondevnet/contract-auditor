"""FastAPI application for the Contract Auditor Dashboard."""
from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from auditor.dashboard.jobs import job_manager
from auditor.dashboard.rendering import STATIC_DIR, templates
from auditor.dashboard.routes import api_router, web_router
from auditor.mode import is_public

log = logging.getLogger("contract_auditor.dashboard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    log.info("Starting Contract Auditor Dashboard")
    job_manager.start()
    try:
        yield
    finally:
        log.info("Shutting down Contract Auditor Dashboard")
        from auditor.discovery_service import shutdown as shutdown_discovery
        shutdown_discovery()
        job_manager.stop()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    if is_public():
        from auditor.public_demo.app import create_public_app
        return create_public_app()

    app = FastAPI(
        title="Contract Auditor Dashboard",
        description="Local-first smart-contract security auditing dashboard",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    app.include_router(web_router)
    app.include_router(api_router, prefix="/api")

    @app.get("/health")
    async def health_check() -> dict[str, str]:
        return {"status": "healthy"}

    return app


def run_dashboard(host: str = "127.0.0.1", port: int = 8080, reload: bool = False) -> None:
    """Run the dashboard server (loopback only in local mode)."""
    if is_public():
        from auditor.public_demo.app import run_public_dashboard
        run_public_dashboard(host=host, port=port, reload=reload)
        return

    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )

    log.info(f"Starting Contract Auditor Dashboard on http://{host}:{port}")
    uvicorn.run(
        "auditor.dashboard.app:create_app",
        host=host,
        port=port,
        reload=reload,
        factory=True,
        log_level="info",
    )


if __name__ == "__main__":
    run_dashboard()
