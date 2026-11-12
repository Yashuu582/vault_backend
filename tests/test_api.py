from fastapi.testclient import TestClient

from app.main import app
from app.models import Role

from .conftest import PASSWORD, make_user


def register(c, email="holder@example.com"):
    return c.post("/api/auth/register",
                  json={"full_name": "Jane Holder", "email": email, "password": PASSWORD})


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"
    r = client.get("/ready")
    assert r.status_code == 200
    assert r.json()["checks"]["database"] == "ok"


def test_register_login_me_logout(client, login):
    r = register(client)
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "ACCOUNT_HOLDER"
    assert client.get("/api/auth/me").status_code == 200  # auto-signed-in after register

    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/auth/me").status_code == 401

    me = login(client, "HOLDER@example.com")  # email is case-insensitive
    assert me["email"] == "holder@example.com"


def test_weak_password_and_duplicate_email(client):
    r = client.post("/api/auth/register", json={"full_name": "A B", "email": "a@example.com", "password": "short"})
    assert r.status_code == 422
    r = client.post("/api/auth/register",
                    json={"full_name": "A B", "email": "a@example.com", "password": "alllowercaseletters"})
    assert r.status_code == 422
    assert register(client, "dup@example.com").status_code == 201
    with TestClient(app) as other:
        assert register(other, "dup@example.com").status_code == 409


def test_bad_login_is_generic_and_rate_limited(client):
    register(client)
    r = client.post("/api/auth/login", json={"identifier": "holder@example.com", "password": "Wrong!Passw0rd"})
    assert r.status_code == 401
    r2 = client.post("/api/auth/login", json={"identifier": "nobody@example.com", "password": "Wrong!Passw0rd"})
    assert r2.json()["detail"] == r.json()["detail"]  # no user enumeration
    codes = [client.post("/api/auth/login", json={"identifier": "holder@example.com", "password": "x"}).status_code
             for _ in range(6)]
    assert 429 in codes


def test_refresh_rotation_and_reuse_detection(client):
    register(client)
    old_refresh = client.cookies.get("bv_refresh")
    assert client.post("/api/auth/refresh").status_code == 200
    new_refresh = client.cookies.get("bv_refresh")
    assert new_refresh and new_refresh != old_refresh

    # Replaying the rotated token revokes the whole family.
    with TestClient(app) as attacker:
        attacker.cookies.set("bv_refresh", old_refresh, path="/api/auth")
        assert attacker.post("/api/auth/refresh").status_code == 401
    client.cookies.delete("bv_access")
    assert client.post("/api/auth/refresh").status_code == 401


def test_rbac(client, login):
    register(client)
    assert client.get("/api/admin/users").status_code == 403
    assert client.get("/api/audit-logs").status_code == 403
    assert client.get("/api/admin/stats").status_code == 403

    make_user("auditor@example.com", Role.AUDITOR)
    with TestClient(app) as auditor:
        login(auditor, "auditor@example.com")
        assert auditor.get("/api/audit-logs").status_code == 200
        assert auditor.get("/api/admin/stats").status_code == 200
        assert auditor.get("/api/admin/users").status_code == 403  # read-only oversight
        assert auditor.get("/api/accounts").status_code == 403


def test_onboarding_flow_and_audit_trail(client, login):
    register(client)
    r = client.post("/api/accounts", json={"type": "SAVINGS", "currency": "EUR", "nickname": "Rainy day"})
    assert r.status_code == 201, r.text
    acct = r.json()
    assert acct["status"] == "PENDING_APPROVAL" and len(acct["account_number"]) == 12

    make_user("admin@example.com", Role.ADMIN)
    with TestClient(app) as admin:
        login(admin, "admin@example.com")
        queue = admin.get("/api/admin/accounts", params={"status": "PENDING_APPROVAL"}).json()
        assert queue["total"] == 1 and queue["items"][0]["owner"]["email"] == "holder@example.com"

        assert admin.post(f"/api/admin/accounts/{acct['id']}/review", json={"decision": "reject"}).status_code == 422
        r = admin.post(f"/api/admin/accounts/{acct['id']}/review", json={"decision": "approve", "note": "KYC ok"})
        assert r.status_code == 200 and r.json()["status"] == "ACTIVE"
        assert admin.post(f"/api/admin/accounts/{acct['id']}/review",
                          json={"decision": "approve"}).status_code == 409
        assert admin.post(f"/api/admin/accounts/{acct['id']}/freeze").json()["status"] == "FROZEN"

        actions = [i["action"] for i in admin.get("/api/audit-logs").json()["items"]]
        for expected in ("auth.register", "account.applied", "account.approved", "account.frozen"):
            assert expected in actions

        stats = admin.get("/api/admin/stats").json()
        assert stats["accounts_by_status"]["FROZEN"] == 1

    assert client.get("/api/accounts").json()[0]["status"] == "FROZEN"


def test_holder_cannot_see_others_accounts(client, login):
    register(client, "a@example.com")
    acct = client.post("/api/accounts", json={"type": "CHECKING"}).json()
    with TestClient(app) as other:
        register(other, "b@example.com")
        assert other.get(f"/api/accounts/{acct['id']}").status_code == 404
        assert other.get("/api/accounts").json() == []


def test_admin_user_management_and_suspension(client, login):
    make_user("admin@example.com", Role.ADMIN)
    login(client, "admin@example.com")
    r = client.post("/api/admin/users", json={"full_name": "New Auditor", "email": "aud@example.com",
                                              "password": PASSWORD, "role": "AUDITOR"})
    assert r.status_code == 201 and r.json()["role"] == "AUDITOR"
    uid = r.json()["id"]

    me = client.get("/api/auth/me").json()
    assert client.patch(f"/api/admin/users/{me['id']}", json={"status": "SUSPENDED"}).status_code == 400

    with TestClient(app) as victim:
        login(victim, "aud@example.com")
        assert client.patch(f"/api/admin/users/{uid}", json={"status": "SUSPENDED"}).status_code == 200
        assert victim.get("/api/auth/me").status_code == 401  # applies immediately
        assert victim.post("/api/auth/refresh").status_code == 401
        r = victim.post("/api/auth/login", json={"identifier": "aud@example.com", "password": PASSWORD})
        assert r.status_code == 403

    found = client.get("/api/admin/users", params={"search": "aud@"}).json()
    assert found["total"] == 1 and found["items"][0]["status"] == "SUSPENDED"


def test_cross_origin_write_blocked(client):
    r = client.post("/api/auth/login", json={"identifier": "x@example.com", "password": "x"},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
