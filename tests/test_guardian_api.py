from fastapi.testclient import TestClient

import guardian_api


def test_health_returns_503_when_pool_is_unavailable():
    guardian_api.db_pool = None
    with TestClient(guardian_api.app) as client:
        response = client.get("/health")

    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable. Please retry shortly."}


def test_events_are_scoped_by_developer_api_key(monkeypatch):
    seen = {}

    def fake_auth(api_key, scope):
        assert api_key == "tenant-key"
        assert scope == "events"
        return guardian_api.DeveloperRecord(id=7, email="tenant@example.com", api_key="tenant-key")

    def fake_read(limit, developer_id):
        seen["limit"] = limit
        seen["developer_id"] = developer_id
        return [{"id": 1, "developer_id": developer_id, "payload": {"message": "ok"}}]

    monkeypatch.setattr(guardian_api, "_authenticate_request", fake_auth)
    monkeypatch.setattr(guardian_api, "_read_events", fake_read)

    with TestClient(guardian_api.app) as client:
        response = client.get("/v1/events?limit=5&api_key=tenant-key")

    assert response.status_code == 200
    assert seen == {"limit": 5, "developer_id": 7}
    assert response.json()[0]["developer_id"] == 7


def test_dashboard_uses_cold_start_message_and_10_second_refresh(monkeypatch):
    monkeypatch.setattr(
        guardian_api,
        "_authenticate_request",
        lambda api_key, scope: guardian_api.DeveloperRecord(id=3, email="dev@example.com", api_key=api_key or ""),
    )

    with TestClient(guardian_api.app) as client:
        response = client.get("/dashboard?api_key=tenant-key")

    assert response.status_code == 200
    assert "Waking up server..." in response.text
    assert "setInterval(refresh, 10000)" in response.text


def test_register_endpoint_requires_master_key(monkeypatch):
    monkeypatch.setattr(guardian_api, "MASTER_API_KEY", "master-key")

    with TestClient(guardian_api.app) as client:
        response = client.post("/v1/register", json={"email": "dev@example.com"})

    assert response.status_code == 401


def test_register_endpoint_returns_developer_key(monkeypatch):
    monkeypatch.setattr(guardian_api, "MASTER_API_KEY", "master-key")
    monkeypatch.setattr(
        guardian_api,
        "_register_developer",
        lambda email: guardian_api.DeveloperRecord(id=5, email=email, api_key="tenant-generated"),
    )

    with TestClient(guardian_api.app) as client:
        response = client.post(
            "/v1/register",
            headers={"X-API-KEY": "master-key"},
            json={"email": "dev@example.com"},
        )

    assert response.status_code == 200
    assert response.json()["api_key"] == "tenant-generated"
