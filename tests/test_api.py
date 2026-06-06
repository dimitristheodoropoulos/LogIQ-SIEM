from __future__ import annotations
import pytest
from unittest.mock import MagicMock
from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token

def test_index_route(api_client, app):
    response = api_client.get("/api/")
    assert response.get_json()["status"] == "success"

def test_export_json_success(api_client, app):
    with app.app_context():
        token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Το /api/export επιστρέφει αρχείο, όχι JSON, οπότε ελέγχουμε status code
    response = api_client.get("/api/export?format=json&time_window=24h", headers=headers)
    assert response.status_code == 200
    assert response.content_type == 'application/json'