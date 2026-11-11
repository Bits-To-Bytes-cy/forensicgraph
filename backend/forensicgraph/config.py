"""Environment-backed application settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ForensicGraph API"
    app_version: str = "0.1.0"
    environment: str = "development"
    database_url: str = (
        "postgresql+psycopg://forensicgraph:forensicgraph@localhost:5432/forensicgraph"
    )
    redis_url: str = "redis://localhost:6379/0"
    minio_endpoint: str = "http://localhost:9000"
    minio_access_key: str = "forensicgraph"
    minio_secret_key: str = "forensicgraph-secret"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="FORENSICGRAPH_",
        extra="ignore",
    )


settings = Settings()
