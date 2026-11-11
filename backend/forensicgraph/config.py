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
    minio_bucket: str = "forensicgraph-evidence"
    evidence_max_upload_bytes: int = 1_073_741_824
    evidence_allowed_media_types: str = (
        "application/octet-stream,application/pdf,application/zip,"
        "text/plain,text/csv,application/json,image/jpeg,image/png"
    )
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = "http://localhost:8000/api/v1/auth/callback"
    oidc_scopes: str = "openid profile email"
    app_secret_key: str = "replace-this-development-secret-with-32-bytes"
    access_token_minutes: int = 10
    refresh_token_days: int = 14

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="FORENSICGRAPH_",
        extra="ignore",
    )


settings = Settings()
