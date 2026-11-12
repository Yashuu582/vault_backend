from decimal import Decimal

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import Role

from .conftest import PASSWORD, make_user


def signup(c, email):
    r = c.post("/api/auth/register", json={"full_name": email.split("@")[0].title() + " User",
                                            "email": email, "password": PASSWORD})
    assert r.status_code == 201, r.text


def open_account(c, currency="USD", acct_type="CHECKING"):
    r = c.post("/api/accounts", json={"type": acct_type, "currency": currency})
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture
def world(login):
    """Two holders with approved accounts, an admin and an auditor, each with their own client."""
    clients = []

    def client():
        c = TestClient(app)
        c.__enter__()
        clients.append(c)
        return c

    alice, bob, admin, auditor = client(), client(), client(), client()
    signup(alice, "alice@example.com")
    signup(bob, "bob@example.com")
    a1 = open_account(alice)
    a2 = open_account(alice, acct_type="SAVINGS")
    a_eur = open_account(alice, currency="EUR")
    b1 = open_account(bob)

    make_user("admin@example.com", Role.ADMIN)
    make_user("auditor@example.com", Role.AUDITOR)
    login(admin, "admin@example.com")
    login(auditor, "auditor@example.com")
    for acct in (a1, a2, a_eur, b1):
        r = admin.post(f"/api/admin/accounts/{acct['id']}/review", json={"decision": "approve"})
        assert r.status_code == 200, r.text

    yield {"alice": alice, "bob": bob, "admin": admin, "auditor": auditor,
           "a1": a1, "a2": a2, "a_eur": a_eur, "b1": b1}
    for c in clients:
        c.__exit__(None, None, None)


def balance(c, account_id):
    return Decimal(next(a for a in c.get("/api/accounts").json() if a["id"] == account_id)["balance"])


def test_admin_deposit_and_withdraw(world):
    admin, alice, a1 = world["admin"], world["alice"], world["a1"]
    r = admin.post(f"/api/admin/accounts/{a1['id']}/deposit", json={"amount": "500.00", "description": "Opening"})
    assert r.status_code == 201, r.text
    txn = r.json()
    assert txn["type"] == "DEPOSIT" and Decimal(txn["balance_after"]) == Decimal("500.00")
    assert txn["reference"].startswith("TX") and txn["owner"]["email"] == "alice@example.com"
    assert txn["initiated_by"]["email"] == "admin@example.com"

    r = admin.post(f"/api/admin/accounts/{a1['id']}/withdraw", json={"amount": "120.50"})
    assert r.status_code == 201 and Decimal(r.json()["balance_after"]) == Decimal("379.50")
    assert balance(alice, a1["id"]) == Decimal("379.50")

    r = admin.post(f"/api/admin/accounts/{a1['id']}/withdraw", json={"amount": "1000"})
    assert r.status_code == 409 and "Insufficient" in r.json()["detail"]
    assert balance(alice, a1["id"]) == Decimal("379.50")  # unchanged


@pytest.mark.parametrize("amount", ["0", "-5", "1.234", "abc", "1000000001"])
def test_invalid_amounts(world, amount):
    r = world["admin"].post(f"/api/admin/accounts/{world['a1']['id']}/deposit", json={"amount": amount})
    assert r.status_code == 422


def test_transfer_between_holders(world):
    admin, alice, bob, a1, b1 = world["admin"], world["alice"], world["bob"], world["a1"], world["b1"]
    admin.post(f"/api/admin/accounts/{a1['id']}/deposit", json={"amount": "300"})

    r = alice.post("/api/transactions/transfer", json={
        "from_account_id": a1["id"], "to_account_number": b1["account_number"],
        "amount": "75.25", "description": "Dinner"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["debit"]["type"] == "TRANSFER_OUT" and Decimal(body["debit"]["balance_after"]) == Decimal("224.75")
    assert body["credit"] is None  # destination belongs to someone else
    assert body["debit"]["owner"] is None  # holders don't get oversight fields

    assert balance(alice, a1["id"]) == Decimal("224.75")
    assert balance(bob, b1["id"]) == Decimal("75.25")

    bob_txns = bob.get("/api/transactions").json()
    assert bob_txns["total"] == 1 and bob_txns["items"][0]["type"] == "TRANSFER_IN"
    assert bob_txns["items"][0]["counterparty_account_number"] == a1["account_number"]
    assert bob_txns["items"][0]["transfer_id"] == body["transfer_id"]


def test_transfer_between_own_accounts_shows_both_sides(world):
    admin, alice, a1, a2 = world["admin"], world["alice"], world["a1"], world["a2"]
    admin.post(f"/api/admin/accounts/{a1['id']}/deposit", json={"amount": "100"})
    r = alice.post("/api/transactions/transfer", json={
        "from_account_id": a1["id"], "to_account_number": a2["account_number"], "amount": "40"})
    assert r.status_code == 201 and r.json()["credit"]["type"] == "TRANSFER_IN"


def test_transfer_rules(world):
    admin, alice, bob = world["admin"], world["alice"], world["bob"]
    a1, a_eur, b1 = world["a1"], world["a_eur"], world["b1"]
    admin.post(f"/api/admin/accounts/{a1['id']}/deposit", json={"amount": "50"})

    def send(c, src, dest_number, amount="10"):
        return c.post("/api/transactions/transfer",
                      json={"from_account_id": src, "to_account_number": dest_number, "amount": amount})

    assert send(alice, a1["id"], b1["account_number"], "50.01").status_code == 409       # insufficient
    assert send(alice, a1["id"], a_eur["account_number"]).status_code == 400              # currency
    assert send(alice, a1["id"], a1["account_number"]).status_code == 400                 # same account
    assert send(alice, a1["id"], "999999999999").status_code == 404                       # unknown
    assert send(bob, a1["id"], b1["account_number"]).status_code == 404                   # not bob's account

    admin.post(f"/api/admin/accounts/{b1['id']}/freeze")
    assert send(alice, a1["id"], b1["account_number"]).status_code == 409                 # frozen destination
    admin.post(f"/api/admin/accounts/{b1['id']}/unfreeze")
    admin.post(f"/api/admin/accounts/{a1['id']}/freeze")
    assert send(alice, a1["id"], b1["account_number"]).status_code == 409                 # frozen source
    assert admin.post(f"/api/admin/accounts/{a1['id']}/deposit", json={"amount": "1"}).status_code == 409


def test_rbac_on_transactions(world):
    alice, bob, auditor, admin, a1 = world["alice"], world["bob"], world["auditor"], world["admin"], world["a1"]
    r = admin.post(f"/api/admin/accounts/{a1['id']}/deposit", json={"amount": "10"})
    txn_id = r.json()["id"]

    # Holders cannot deposit; auditors cannot post anything.
    assert alice.post(f"/api/admin/accounts/{a1['id']}/deposit", json={"amount": "10"}).status_code == 403
    assert auditor.post(f"/api/admin/accounts/{a1['id']}/deposit", json={"amount": "10"}).status_code == 403
    assert auditor.post("/api/transactions/transfer", json={
        "from_account_id": a1["id"], "to_account_number": world["b1"]["account_number"],
        "amount": "1"}).status_code == 403

    # Bob cannot see Alice's transaction.
    assert bob.get(f"/api/transactions/{txn_id}").status_code == 404
    assert bob.get("/api/transactions").json()["total"] == 0

    # Auditor sees everything, with owner and initiator details.
    seen = auditor.get(f"/api/transactions/{txn_id}").json()
    assert seen["owner"]["email"] == "alice@example.com" and seen["initiated_by"]["email"] == "admin@example.com"
    assert auditor.get("/api/admin/stats").json()["transactions_total"] == 1


def test_oversight_filters(world):
    admin, auditor, alice = world["admin"], world["auditor"], world["alice"]
    a1, b1 = world["a1"], world["b1"]
    admin.post(f"/api/admin/accounts/{a1['id']}/deposit", json={"amount": "200"})
    admin.post(f"/api/admin/accounts/{b1['id']}/deposit", json={"amount": "5"})
    alice.post("/api/transactions/transfer", json={
        "from_account_id": a1["id"], "to_account_number": b1["account_number"], "amount": "20"})

    def total(**params):
        return auditor.get("/api/transactions", params=params).json()["total"]

    assert total() == 4
    assert total(type="DEPOSIT") == 2
    assert total(owner="bob") == 2
    assert total(account_number=a1["account_number"]) == 2
    assert total(min_amount="20", max_amount="100") == 2   # transfer out + in
    ref = auditor.get("/api/transactions", params={"type": "TRANSFER_OUT"}).json()["items"][0]["reference"]
    assert total(reference=ref.lower()) == 1
