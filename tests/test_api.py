"""
Week 1-2 tests — run with: pytest tests/ -v
Uses TestClient (no real DB needed with SQLite override).
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base, get_db
from app.main import app

# Use SQLite in-memory for tests
SQLALCHEMY_TEST_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_TEST_URL, connect_args={"check_same_thread": False})
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


client = TestClient(app)


# ──────────────────────────────────────────────
# Auth tests
# ──────────────────────────────────────────────

def test_register_and_login():
    r = client.post("/api/v1/auth/register", json={
        "email": "test@example.com",
        "password": "securepass123",
        "full_name": "Test User",
    })
    assert r.status_code == 201
    data = r.json()
    assert data["email"] == "test@example.com"
    assert data["plan"] == "free"

    r = client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "securepass123",
    })
    assert r.status_code == 200
    assert "access_token" in r.json()


def test_duplicate_register():
    for _ in range(2):
        r = client.post("/api/v1/auth/register", json={
            "email": "dup@example.com",
            "password": "password123",
        })
    assert r.status_code == 400


def test_wrong_password():
    client.post("/api/v1/auth/register", json={"email": "a@b.com", "password": "pass1234"})
    r = client.post("/api/v1/auth/login", json={"email": "a@b.com", "password": "wrong"})
    assert r.status_code == 401


def _auth_header(email="user@test.com", password="testpass99"):
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ──────────────────────────────────────────────
# Workspace tests
# ──────────────────────────────────────────────

def test_create_and_list_workspace():
    headers = _auth_header()
    r = client.post("/api/v1/workspaces", json={"name": "My Company"}, headers=headers)
    assert r.status_code == 201
    ws_id = r.json()["id"]

    r = client.get("/api/v1/workspaces", headers=headers)
    assert r.status_code == 200
    assert any(w["id"] == ws_id for w in r.json())


def test_workspace_isolation():
    h1 = _auth_header("u1@test.com", "pass1111")
    h2 = _auth_header("u2@test.com", "pass2222")

    r = client.post("/api/v1/workspaces", json={"name": "User1 WS"}, headers=h1)
    ws_id = r.json()["id"]

    # User 2 cannot see user 1's workspace
    r = client.get(f"/api/v1/workspaces/{ws_id}", headers=h2)
    assert r.status_code == 404


# ──────────────────────────────────────────────
# Domain tests
# ──────────────────────────────────────────────

def test_add_domain(monkeypatch):
    # Patch Celery task so it doesn't actually run
    monkeypatch.setattr("app.api.v1.endpoints.domains.run_full_scan.delay", lambda *a, **k: type("T", (), {"id": "x"})())

    headers = _auth_header()
    ws = client.post("/api/v1/workspaces", json={"name": "WS"}, headers=headers).json()

    r = client.post(
        f"/api/v1/workspaces/{ws['id']}/domains",
        json={"fqdn": "example.com"},
        headers=headers,
    )
    assert r.status_code == 201
    assert r.json()["fqdn"] == "example.com"


def test_free_plan_domain_limit(monkeypatch):
    monkeypatch.setattr("app.api.v1.endpoints.domains.run_full_scan.delay", lambda *a, **k: type("T", (), {"id": "x"})())

    headers = _auth_header("limit@test.com", "limitpass")
    ws = client.post("/api/v1/workspaces", json={"name": "WS"}, headers=headers).json()

    client.post(f"/api/v1/workspaces/{ws['id']}/domains", json={"fqdn": "first.com"}, headers=headers)
    r = client.post(f"/api/v1/workspaces/{ws['id']}/domains", json={"fqdn": "second.com"}, headers=headers)
    assert r.status_code == 402  # plan limit hit


def test_domain_fqdn_normalisation(monkeypatch):
    monkeypatch.setattr("app.api.v1.endpoints.domains.run_full_scan.delay", lambda *a, **k: type("T", (), {"id": "x"})())

    headers = _auth_header("norm@test.com", "normpass1")
    ws = client.post("/api/v1/workspaces", json={"name": "WS"}, headers=headers).json()

    r = client.post(
        f"/api/v1/workspaces/{ws['id']}/domains",
        json={"fqdn": "https://Example.COM/"},
        headers=headers,
    )
    assert r.status_code == 201
    assert r.json()["fqdn"] == "example.com"
