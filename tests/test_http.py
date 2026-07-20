"""Application HTTP contract tests."""

from httpx import ASGITransport, AsyncClient

from backend.main import app


def test_application_metadata() -> None:
    assert app.title == "CyberShield AI"
    assert app.version == "0.1.0"


async def test_home_page() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "CyberShield AI" in response.text
    assert response.headers["content-type"].startswith("text/html")


async def test_health_contract() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.1.0"}


async def test_status_reports_unimplemented_integrations_as_planned() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["phase"] == "foundation"
    assert payload["capabilities"][0] == {
        "name": "FastAPI application",
        "status": "available",
    }
    assert all(item["status"] == "planned" for item in payload["capabilities"][1:])
