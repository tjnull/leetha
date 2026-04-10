import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create a test client with mocked app_instance."""
    from leetha.ui.web.app import fastapi_app
    import leetha.ui.web.app as web_app
    from leetha.capture.remote.server import RemoteSensorManager

    mock_app = MagicMock()
    mock_app._remote_sensor_manager = RemoteSensorManager()
    mock_app.data_dir = MagicMock()
    web_app.app_instance = mock_app
    web_app._auth_enabled = False

    return TestClient(fastapi_app)


def test_list_sensors_empty(client):
    resp = client.get("/api/remote/sensors")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_sensors_with_connected(client):
    from leetha.ui.web import app as web_app
    mgr = web_app.app_instance._remote_sensor_manager
    mgr.register("test-sensor", "10.0.0.1")

    resp = client.get("/api/remote/sensors")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["name"] == "test-sensor"
