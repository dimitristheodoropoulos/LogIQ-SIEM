from __future__ import annotations
from unittest.mock import patch, MagicMock
import pytest
from werkzeug.security import generate_password_hash

def test_register_success(api_client, app):
    app.db.find_by_username = MagicMock(return_value=None)
    app.db.insert_user = MagicMock(return_value=1)
    
    response = api_client.post("/api/register", json={"username": "newuser", "password": "newpassword123"})
    
    assert response.status_code == 201
    assert "message" in response.json
    assert response.json["message"] == "Επιτυχής εγγραφή χρήστη"

def test_register_existing_user(api_client, app):
    app.db.find_by_username = MagicMock(return_value={"username": "existinguser", "password": generate_password_hash("password123")})
    
    response = api_client.post("/api/register", json={"username": "existinguser", "password": "password123"})
    
    assert response.status_code == 409
    assert response.json["error"] == "Το όνομα χρήστη υπάρχει ήδη"

def test_register_invalid_data(api_client, app):
    response = api_client.post("/api/register", json={"username": "user", "password": "123"})
    assert response.status_code == 422
    assert "error" in response.json

def test_login_success(api_client, app):
    username = "testuser"
    password = "testpassword"
    hashed_password = generate_password_hash(password)
    app.db.find_by_username = MagicMock(return_value={"username": username, "password": hashed_password})
    
    response = api_client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200
    assert "access_token" in response.json

def test_login_invalid_credentials(api_client, app):
    username = "testuser"
    password = "testpassword"
    wrong_password = "wrongpassword"
    hashed_password = generate_password_hash(password)
    app.db.find_by_username = MagicMock(return_value={"username": username, "password": hashed_password})

    response = api_client.post("/api/login", json={"username": username, "password": wrong_password})
    assert response.status_code == 401
    assert response.json["error"] == "Λανθασμένο όνομα χρήστη ή κωδικός"

def test_login_user_not_found(api_client, app):
    app.db.find_by_username = MagicMock(return_value=None)
    response = api_client.post("/api/login", json={"username": "nonexistent", "password": "password"})
    assert response.status_code == 401
    assert response.json["error"] == "Λανθασμένο όνομα χρήστη ή κωδικός"