import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from app.main import app
from app.routers import auth as auth_router

from .conftest import PASSWORD

BACKEND_DIR = Path(__file__).resolve().parent.parent


def signup(c, email="jane@example.com", username=None):
    body = {"full_name": "Jane Holder", "email": email, "password": PASSWORD}
    if username is not None:
        body["username"] = username
    return c.post("/api/auth/register", json=body)


def capture_reset_links(monkeypatch):
    sent = []
    monkeypatch.setattr(auth_router, "send_password_reset",
                        lambda to, name, link, ttl: sent.append((to, link)))
    return sent


def token_from(link: str) -> str:
    return parse_qs(urlparse(link).query)["token"][0]


def test_signup_with_username_and_sign_in_with_either(client):
    r = signup(client, username="Jane.Doe")
    assert r.status_code == 201, r.text
    assert r.json()["username"] == "jane.doe"  # normalized to lowercase
    client.post("/api/auth/logout")

    with TestClient(app) as c:
        assert c.post("/api/auth/login", json={"identifier": "JANE.DOE", "password": PASSWORD}).status_code == 200
    with TestClient(app) as c:
        assert c.post("/api/auth/login",
                      json={"identifier": "jane@example.com", "password": PASSWORD}).status_code == 200


def test_signup_username_rules(client):
    assert signup(client, "a@example.com", username="ab").status_code == 422          # too short
    assert signup(client, "b@example.com", username="has space").status_code == 422  # bad chars
    assert signup(client, "c@example.com", username="").status_code == 201            # optional
    with TestClient(app) as other:
        assert signup(other, "d@example.com", username="taken").status_code == 201
    with TestClient(app) as other:
        r = signup(other, "e@example.com", username="TAKEN")
        assert r.status_code == 409 and "username" in r.json()["detail"].lower()


def test_forgot_and_reset_password(client, monkeypatch):
    sent = capture_reset_links(monkeypatch)
    signup(client, username="jane")
    client.post("/api/auth/logout")

    # Unknown accounts get the same response and no email.
    unknown = client.post("/api/auth/forgot-password", json={"identifier": "nobody@example.com"})
    known = client.post("/api/auth/forgot-password", json={"identifier": "jane"})
    assert unknown.status_code == known.status_code == 202
    assert unknown.json() == known.json()
    assert len(sent) == 1 and sent[0][0] == "jane@example.com"
    assert sent[0][1].startswith("http://localhost:5173/reset-password?token=")
    token = token_from(sent[0][1])

    weak = client.post("/api/auth/reset-password", json={"token": token, "new_password": "short"})
    assert weak.status_code == 422

    new_pw = "Brand!New2Passw0rd"
    r = client.post("/api/auth/reset-password", json={"token": token, "new_password": new_pw})
    assert r.status_code == 200, r.text
    # Single use.
    again = client.post("/api/auth/reset-password", json={"token": token, "new_password": new_pw})
    assert again.status_code == 400

    with TestClient(app) as c:
        assert c.post("/api/auth/login", json={"identifier": "jane", "password": PASSWORD}).status_code == 401
        assert c.post("/api/auth/login", json={"identifier": "jane", "password": new_pw}).status_code == 200


def test_reset_revokes_sessions_and_old_links(client, monkeypatch):
    sent = capture_reset_links(monkeypatch)
    signup(client)  # client stays signed in
    client.post("/api/auth/forgot-password", json={"identifier": "jane@example.com"})
    client.post("/api/auth/forgot-password", json={"identifier": "jane@example.com"})
    first, second = token_from(sent[0][1]), token_from(sent[1][1])

    # Only the newest link works.
    assert client.post("/api/auth/reset-password",
                       json={"token": first, "new_password": "Brand!New2Passw0rd"}).status_code == 400
    assert client.post("/api/auth/reset-password",
                       json={"token": second, "new_password": "Brand!New2Passw0rd"}).status_code == 200
    # The existing session's refresh token was revoked.
    assert client.post("/api/auth/refresh").status_code == 401


def test_forgot_password_rate_limited(client, monkeypatch):
    capture_reset_links(monkeypatch)
    codes = [client.post("/api/auth/forgot-password", json={"identifier": "x@example.com"}).status_code
             for _ in range(5)]
    assert codes[:3] == [202, 202, 202] and 429 in codes


def test_create_admin_script_with_username(client):
    env = {**os.environ, "BV_ADMIN_PASSWORD": "admin@1818", "PYTHONDONTWRITEBYTECODE": "1"}
    cmd = [sys.executable, "-m", "scripts.create_admin", "--email", "admin@example.com",
           "--username", "admin", "--name", "Vault Admin"]
    out = subprocess.run(cmd, cwd=BACKEND_DIR, env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "WARNING: weak admin password" in out.stdout and "Created ADMIN user admin" in out.stdout

    again = subprocess.run(cmd, cwd=BACKEND_DIR, env=env, capture_output=True, text=True)
    assert "already exists" in again.stdout  # idempotent

    r = client.post("/api/auth/login", json={"identifier": "admin", "password": "admin@1818"})
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "ADMIN" and r.json()["username"] == "admin"
    assert client.get("/api/admin/users").status_code == 200
