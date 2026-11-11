import pytest
from fastapi.testclient import TestClient
from forensicgraph.app import app
from forensicgraph.db import Base, get_db
from forensicgraph.models import (
    User,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSession = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)


@pytest.fixture(autouse=True)
def database():
    Base.metadata.create_all(_engine)

    def override_get_db():
        with TestingSession() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(_engine)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def seeded_user():
    with TestingSession() as session:
        user = User(
            id="user-1",
            email="owner@example.com",
            display_name="Owner",
            is_active=True,
            created_at=__import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ),
        )
        session.add(user)
        session.commit()
    return user
