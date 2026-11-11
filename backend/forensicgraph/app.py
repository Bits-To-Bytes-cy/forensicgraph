"""FastAPI application entrypoint for Phase 0."""

from fastapi import FastAPI

from forensicgraph.config import settings
from forensicgraph.health import check_database, check_minio, check_redis

app = FastAPI(title=settings.app_name, version=settings.app_version)


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
