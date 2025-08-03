from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token, decode_token, JWTManager 
from datetime import timedelta
from flask import Flask # Import Flask here, though 'app' fixture provides it

from logiq.db.db_sqlite import SQLiteDatabase
from logiq.api.routes import api_blueprint 

# The 'app' fixture from conftest.py will be used automatically.
# No need for mock_app_for_jwt_auth fixture here.

@pytest.fixture
def mock_db_for_jwt_auth(app): # Use the central 'app' fixture
    # Ensure app.db is a MagicMock and reset it for each test function
    if hasattr(app, 'db') and isinstance(app.db, MagicMock):
        app.db.reset_mock() 
        # Re-set default return values after reset_mock() as tests might override them
        app.db.insert_user.return_value = 1
        app.db.find_by_username.return_value = None
        app.db.add_event.return_value = 1
        app.db.get_all_events.return_value = []
        app.db.get_alerts.return_value = []
    return app.db

def test_register_login_and_access(client, mock_db_for_jwt_auth, app): # Use the central 'client' and 'app' fixtures
    """Full flow test: register, login, then access protected route."""
    # 1. Register - Ensure user does not exist before attempting to register
    mock_db_for_jwt_auth.find_by_username.return_value = None 
    register_response = client.post("/api/register", json={"username": "fulltestuser", "password": "password123"})
    assert register_response.status_code == 201
    mock_db_for_jwt_auth.insert_user.assert_called_once()
    
    # After successful registration, set up mock for subsequent login attempt
    hashed_password = generate_password_hash("password123")
    mock_db_for_jwt_auth.find_by_username.return_value = {"username": "fulltestuser", "password": hashed_password}

    # 2. Login
    login_response = client.post("/api/login", json={"username": "fulltestuser", "password": "password123"})
    assert login_response.status_code == 200
    assert "access_token" in login_response.json
    token = login_response.json["access_token"]
    
    # 3. Access Protected Route
    headers = {"Authorization": f"Bearer {token}"}
    event_data = [{"timestamp": "2023-01-01T12:00:00Z", "hostname": "test", "event_type": "test_event", "message": "Protected access"}]
    
    app.db.add_event.reset_mock() # Use app.db directly
    add_event_response = client.post("/api/events", json=event_data, headers=headers)
    assert add_event_response.status_code == 201
    assert "Events added successfully" in add_event_response.json["message"]
    app.db.add_event.assert_called_once()


def test_login_and_access_with_correct_credentials(client, mock_db_for_jwt_auth, app): # Use the central 'client' and 'app' fixtures
    """Test login and access with pre-existing user."""
    hashed_password = generate_password_hash("password123")
    mock_db_for_jwt_auth.find_by_username.return_value = {"username": "existinguser", "password": hashed_password}
    
    # Login
    login_response = client.post("/api/login", json={"username": "existinguser", "password": "password123"})
    assert login_response.status_code == 200
    token = login_response.json["access_token"]
    
    # Access Protected Route
    headers = {"Authorization": f"Bearer {token}"}
    event_data = [{"timestamp": "2023-01-01T12:00:00Z", "hostname": "test", "event_type": "test_event", "message": "Protected access"}]
    
    app.db.add_event.reset_mock() # Use app.db directly
    add_event_response = client.post("/api/events", json=event_data, headers=headers)
    assert add_event_response.status_code == 201
    app.db.add_event.assert_called_once()


def test_login_and_access_with_incorrect_password(client, mock_db_for_jwt_auth): # Use the central 'client' fixture
    """Test login failure due to incorrect password."""
    hashed_password = generate_password_hash("correctpassword")
    mock_db_for_jwt_auth.find_by_username.return_value = {"username": "testuser", "password": hashed_password}
    
    login_response = client.post("/api/login", json={"username": "testuser", "password": "wrongpassword"})
    assert login_response.status_code == 401
    assert "Λανθασμένο όνομα χρήστη ή κωδικός" in login_response.json["error"]

def test_access_protected_route_without_token(client): # Use the central 'client' fixture
    """Test accessing protected route without any token."""
    event_data = [{"timestamp": "2023-01-01T12:00:00Z", "hostname": "test", "event_type": "test_event", "message": "Protected access"}]
    response = client.post("/api/events", json=event_data)
    assert response.status_code == 401
    assert b"Missing Authorization Header" in response.data

def test_access_protected_route_with_invalid_token(client): # Use the central 'client' fixture
    """Test accessing protected route with an invalid token."""
    headers = {"Authorization": "Bearer invalid.token.string"}
    event_data = [{"timestamp": "2023-01-01T12:00:00Z", "hostname": "test", "event_type": "test_event", "message": "Protected access"}]
    response = client.post("/api/events", json=event_data, headers=headers)
    assert response.status_code == 401 # Expected 401 for invalid JWT as per Flask-JWT-Extended and conftest setup
    assert b"Invalid JWT" in response.data
