from forensicgraph.config import Settings


def test_settings_use_environment_prefix(monkeypatch) -> None:
    monkeypatch.setenv("FORENSICGRAPH_ENVIRONMENT", "test")
    monkeypatch.setenv(
        "FORENSICGRAPH_DATABASE_URL", "postgresql+psycopg://user:pass@db/test"
    )
    settings = Settings()

    assert settings.environment == "test"
    assert settings.database_url.endswith("@db/test")
