"""Tests for the OSV Security Platform API."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import Base, get_db

TEST_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_list_scans_empty(client):
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


def test_create_scan(client):
    resp = client.post("/api/scans", json={
        "scan_type": "dependency",
        "target": "test-packages",
        "packages": [
            {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}
        ]
    })
    assert resp.status_code in (200, 201, 202)
    data = resp.json()
    assert data["name"] == "test-packages"
    assert data["scan_type"] == "dependency"
    assert "id" in data
    # Scan is enqueued asynchronously; initial status must be pending
    assert data["status"] == "pending"


def test_list_scans_filter_by_scan_type(client):
    """GET /api/scans?scan_type=dependency should only return dependency scans."""
    resp = client.get("/api/scans", params={"scan_type": "dependency"})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    for scan in data:
        assert scan["scan_type"] == "dependency"


def test_list_scans_filter_unknown_type(client):
    """An unrecognised scan_type should return 400 Bad Request."""
    resp = client.get("/api/scans", params={"scan_type": "nonexistent"})
    assert resp.status_code == 400


def test_list_scans_filter_by_status(client):
    """GET /api/scans?status=pending should only return pending scans."""
    resp = client.get("/api/scans", params={"status": "pending"})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    for scan in data:
        assert scan["status"] == "pending"


def test_list_scans_filter_unknown_status(client):
    """An unrecognised status should return 400 Bad Request."""
    resp = client.get("/api/scans", params={"status": "nonexistent"})
    assert resp.status_code == 400


def test_list_scans_severity_counts(client):
    """Scan summaries in the list endpoint must include severity count fields."""
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    data = resp.json()
    for scan in data:
        assert "critical_count" in scan
        assert "high_count" in scan
        assert "medium_count" in scan
        assert "low_count" in scan
        assert isinstance(scan["critical_count"], int)
        assert isinstance(scan["high_count"], int)
        assert isinstance(scan["medium_count"], int)
        assert isinstance(scan["low_count"], int)


def test_vuln_endpoint_not_found(client):
    """GET /api/vulns/{id} with an unknown ID should proxy a 404."""
    resp = client.get("/api/vulns/DOES-NOT-EXIST-00000")
    # Either our backend 404 or the OSV service is unreachable (503).
    assert resp.status_code in (404, 503)


def test_list_policies(client):
    resp = client.get("/api/policies")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


def test_create_policy(client):
    resp = client.post("/api/policies", json={
        "name": "Test Policy",
        "description": "Block critical findings",
        "enabled": True,
        "action": "block",
        "rules": [
            {"type": "severity_threshold", "min_severity": "CRITICAL"}
        ]
    })
    assert resp.status_code in (200, 201)
    data = resp.json()
    assert data["name"] == "Test Policy"
    assert data["enabled"] is True


def test_dashboard(client):
    resp = client.get("/api/reports/dashboard")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_scans" in data
    assert "total_findings" in data
    assert "critical_count" in data


def test_audit_log(client):
    resp = client.get("/api/reports/audit-log")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_delete_scan(client):
    """DELETE /api/scans/{id} should remove the scan and return 204."""
    # Create a scan to delete
    create_resp = client.post("/api/scans", json={
        "scan_type": "dependency",
        "target": "delete-test",
        "packages": [],
    })
    assert create_resp.status_code in (200, 201, 202)
    scan_id = create_resp.json()["id"]

    # Delete the scan
    del_resp = client.delete(f"/api/scans/{scan_id}")
    assert del_resp.status_code == 204

    # Verify it's gone
    get_resp = client.get(f"/api/scans/{scan_id}")
    assert get_resp.status_code == 404


def test_delete_scan_not_found(client):
    """DELETE /api/scans/{id} with a nonexistent ID should return 404."""
    resp = client.delete("/api/scans/does-not-exist")
    assert resp.status_code == 404


def test_rerun_scan_creates_new_scan(client):
    """POST /api/scans/{id}/rerun should create a new scan with the same target/type."""
    # Create an original scan
    create_resp = client.post("/api/scans", json={
        "scan_type": "dependency",
        "target": "rerun-test-target",
        "packages": [{"name": "flask", "version": "2.0.0", "ecosystem": "PyPI"}],
    })
    assert create_resp.status_code in (200, 201, 202)
    original = create_resp.json()
    original_id = original["id"]

    # Rerun it
    rerun_resp = client.post(f"/api/scans/{original_id}/rerun")
    assert rerun_resp.status_code == 202
    rerun_data = rerun_resp.json()

    # A brand-new scan must be created
    assert rerun_data["id"] != original_id
    assert rerun_data["scan_type"] == original["scan_type"]
    assert rerun_data["target"] == original["target"]
    assert rerun_data["status"] == "pending"

    # The original scan must still exist and be unchanged
    orig_resp = client.get(f"/api/scans/{original_id}")
    assert orig_resp.status_code == 200


def test_rerun_scan_not_found(client):
    """POST /api/scans/{id}/rerun with a nonexistent ID should return 404."""
    resp = client.post("/api/scans/does-not-exist/rerun")
    assert resp.status_code == 404
