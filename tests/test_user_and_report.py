from __future__ import annotations
import pytest
from unittest.mock import patch, MagicMock
from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token

def test_login_and_add_event(api_client, app):
    username = "testuser"
    app.db.find_by_username = MagicMock(return_value={"username": username, "password": generate_password_hash("testpassword")})
    app.db.add_event = MagicMock(return_value=1)
    
    login_response = api_client.post("/api/login", json={"username": username, "password": "testpassword"})
    access_token = login_response.json["access_token"]

    # Συμπερίληψη των required πεδίων του schema
    event_data = {
        "timestamp": "2023-01-01T12:00:00Z", 
        "event_type": "login_success",
        "hostname": "test-host",
        "message": "User logged in"
    }
    headers = {"Authorization": f"Bearer {access_token}"}
    
    event_response = api_client.post("/api/events", json=[event_data], headers=headers)
    assert event_response.status_code == 201