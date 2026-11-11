"""FastAPI application entrypoint for Phase 0."""

from fastapi import FastAPI

from forensicgraph.api.routes.auth import router as auth_router
from forensicgraph.api.routes.cases import router as cases_router
from forensicgraph.api.routes.evidence import router as evidence_router
from forensicgraph.api.routes.organizations import router as organizations_router
from forensicgraph.config import settings
from forensicgraph.health import check_database, check_minio, check_redis

app = FastAPI(title=settings.app_name, version=settings.app_version)
app.include_router(auth_router, prefix="/api/v1")
app.include_router(cases_router, prefix="/api/v1")
app.include_router(evidence_router, prefix="/api/v1")
app.include_router(organizations_router, prefix="/api/v1")


@app.get("/health", tags=["system"])
def health() -> dict[str, object]:
    services = {
        "database": check_database().as_dict(),
        "redis": check_redis().as_dict(),
        "minio": check_minio().as_dict(),
    }
    services_ok = all(item["status"] == "ok" for item in services.values())
    overall = "ok" if services_ok else "degraded"
    return {
        "status": overall,
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "services": services,
    }
