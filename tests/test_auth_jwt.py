from __future__ import annotations
import pytest
from unittest.mock import MagicMock
from werkzeug.security import generate_password_hash

@pytest.fixture
def mock_db_for_jwt_auth(app):
    app.db.insert_user = MagicMock(return_value=1)
    app.db.find_by_username = MagicMock(return_value=None)
    app.db.add_event = MagicMock(return_value=1)
    app.db.get_all_events = MagicMock(return_value=[])
    app.db.get_alerts = MagicMock(return_value=[])
    return app.db

def test_register_login_and_access(api_client, app, mock_db_for_jwt_auth):
    mock_db_for_jwt_auth.find_by_username.return_value = None 
    register_response = api_client.post("/api/register", json={"username": "fulltestuser", "password": "password123"})
    assert register_response.status_code == 201
    
    hashed_password = generate_password_hash("password123")
    mock_db_for_jwt_auth.find_by_username.return_value = {"username": "fulltestuser", "password": hashed_password}

    login_response = api_client.post("/api/login", json={"username": "fulltestuser", "password": "password123"})
    assert login_response.status_code == 200
    token = login_response.json["access_token"]
    
    headers = {"Authorization": f"Bearer {token}"}
    event_data = [{"timestamp": "2023-01-01T12:00:00Z", "hostname": "test", "event_type": "test_event", "message": "Protected access"}]
    
    add_event_response = api_client.post("/api/events", json=event_data, headers=headers)
    assert add_event_response.status_code == 201

def test_login_and_access_with_correct_credentials(api_client, app, mock_db_for_jwt_auth):
    hashed_password = generate_password_hash("password123")
    mock_db_for_jwt_auth.find_by_username.return_value = {"username": "existinguser", "password": hashed_password}
    
    login_response = api_client.post("/api/login", json={"username": "existinguser", "password": "password123"})
    assert login_response.status_code == 200
    token = login_response.json["access_token"]
    
    headers = {"Authorization": f"Bearer {token}"}
    event_data = [{"timestamp": "2023-01-01T12:00:00Z", "hostname": "test", "event_type": "test_event", "message": "Protected access"}]
    
    add_event_response = api_client.post("/api/events", json=event_data, headers=headers)
    assert add_event_response.status_code == 201

def test_login_and_access_with_incorrect_password(api_client, app, mock_db_for_jwt_auth):
    hashed_password = generate_password_hash("correctpassword")
    mock_db_for_jwt_auth.find_by_username.return_value = {"username": "testuser", "password": hashed_password}
    
    login_response = api_client.post("/api/login", json={"username": "testuser", "password": "wrongpassword"})
    assert login_response.status_code == 401
    assert "Λανθασμένο όνομα χρήστη ή κωδικός" in login_response.json["error"]

def test_access_protected_route_without_token(api_client, app):
    event_data = [{"timestamp": "2023-01-01T12:00:00Z", "hostname": "test", "event_type": "test_event", "message": "Protected access"}]
    response = api_client.post("/api/events", json=event_data)
    assert response.status_code == 401

def test_access_protected_route_with_invalid_token(api_client, app):
    headers = {"Authorization": "Bearer invalid.token.string"}
    event_data = [{"timestamp": "2023-01-01T12:00:00Z", "hostname": "test", "event_type": "test_event", "message": "Protected access"}]
    response = api_client.post("/api/events", json=event_data, headers=headers)
    assert response.status_code == 422