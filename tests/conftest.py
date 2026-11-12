"""Test setup: runs the API against a throwaway SQLite database (no Postgres/Redis needed)."""

import os
import tempfile
from pathlib import Path

_DB_FILE = Path(tempfile.mkdtemp()) / "test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_DB_FILE.as_posix()}"
os.environ["JWT_SECRET"] = "test-secret-" + "x" * 40
os.environ["REDIS_PORT"] = ""  # force in-memory rate limiting, even if Backend/.env sets a port

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Base, Role, User  # noqa: E402
from app.rate_limit import limiter  # noqa: E402
from app.security import hash_password  # noqa: E402

PASSWORD = "Str0ng!Passw0rd"


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    limiter.reset()
    yield


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def make_user(email: str, role: Role) -> None:
    with SessionLocal() as db:
        db.add(User(email=email, full_name=email.split("@")[0].title(), password_hash=hash_password(PASSWORD),
                    role=role))
        db.commit()


@pytest.fixture
def login():
    def _login(c: TestClient, email: str, password: str = PASSWORD):
        r = c.post("/api/auth/login", json={"identifier": email, "password": password})
        assert r.status_code == 200, r.text
        return r.json()

    return _login
