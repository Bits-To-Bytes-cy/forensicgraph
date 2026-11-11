"""Infrastructure health checks."""

from dataclasses import dataclass
from urllib.request import urlopen

from redis import Redis
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from forensicgraph.config import settings
from forensicgraph.db import engine


@dataclass(frozen=True)
class ServiceHealth:
    status: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"status": self.status, "detail": self.detail}


def check_database() -> ServiceHealth:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return ServiceHealth("ok", "PostgreSQL connection succeeded")
    except SQLAlchemyError as error:
        return ServiceHealth("unavailable", error.__class__.__name__)


def check_redis() -> ServiceHealth:
    try:
        Redis.from_url(settings.redis_url, socket_connect_timeout=1).ping()
        return ServiceHealth("ok", "Redis ping succeeded")
    except Exception as error:
        return ServiceHealth("unavailable", error.__class__.__name__)


def check_minio() -> ServiceHealth:
    try:
        with urlopen(
            f"{settings.minio_endpoint}/minio/health/live", timeout=1
        ) as response:
            if response.status != 200:
                return ServiceHealth("unavailable", f"HTTP {response.status}")
        return ServiceHealth("ok", "MinIO health endpoint succeeded")
    except Exception as error:
        return ServiceHealth("unavailable", error.__class__.__name__)
