import pytest
from unittest.mock import patch, MagicMock

def test_register_success(api_client, app):
    app.db.find_by_username = MagicMock(return_value=None)
    response = api_client.post("/api/register", json={"username": "new", "password": "password123"})
    assert response.status_code == 201
    assert response.get_json()["message"] == "Επιτυχής εγγραφή χρήστη"

def test_login_success(api_client, app):
    app.db.find_by_username = MagicMock(return_value={"username": "test", "password": "hash"})
    with patch('api.routes.check_password_hash', return_value=True):
        response = api_client.post("/api/login", json={"username": "test", "password": "password"})
        assert response.status_code == 200
        assert "access_token" in response.get_json()