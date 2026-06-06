from __future__ import annotations

import json
from unittest.mock import patch, MagicMock
import pytest
from flask import Flask, current_app # Import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token
from typing import cast # Import cast for type hinting

# Removed local mock_db_instance, mock_mongo_db_instance, and app fixtures
# as they are now provided by conftest.py

# The 'app' and 'client' fixtures will be automatically discovered from conftest.py

def test_register_success(client, app): # Use client and app fixtures from conftest.py
    """Test successful user registration."""
    # Use the app's mocked db instance provided by conftest.py
    app.db.find_by_username.return_value = None # User does not exist
    app.db.insert_user.return_value = 1 # Successfully inserted
    
    response = client.post("/api/register", json={"username": "newuser", "password": "newpassword123"})
    
    assert response.status_code == 201
    assert response.content_type == 'application/json'
    assert "message" in response.json
    assert response.json["message"] == "Επιτυχής εγγραφή χρήστη" # Harmonize message
    assert "user_id" in response.json
    app.db.find_by_username.assert_called_once_with("newuser")
    app.db.insert_user.assert_called_once()

def test_register_existing_user(client, app): # Use client and app fixtures
    """Test registration of an existing user."""
    app.db.find_by_username.return_value = {"username": "existinguser", "password": generate_password_hash("password123")} # User exists
    
    response = client.post("/api/register", json={"username": "existinguser", "password": "password123"})
    
    assert response.status_code == 409 # Expecting 409 Conflict
    assert response.content_type == 'application/json'
    assert "error" in response.json
    assert response.json["error"] == "Το όνομα χρήστη υπάρχει ήδη" # Harmonize message
    app.db.find_by_username.assert_called_once_with("existinguser")
    app.db.insert_user.assert_not_called() # Should not try to insert

def test_register_invalid_data(client): # Use client fixture
    """Test user registration with invalid data (e.g., too short password)."""
    response = client.post("/api/register", json={"username": "user", "password": "123"}) # Password too short
    
    assert response.status_code == 422
    assert response.content_type == 'application/json'
    assert "error" in response.json
    assert "minLength" in response.json["error"] # Check for schema validation error message

def test_login_success(client, app): # Use client and app fixtures
    """Test successful user login."""
    username = "testuser"
    password = "testpassword"
    hashed_password = generate_password_hash(password)

    app.db.find_by_username.return_value = {
        "username": username,
        "password": hashed_password
    }
    
    with patch('werkzeug.security.check_password_hash', return_value=True):
        response = client.post("/api/login", json={"username": username, "password": password})
        
        assert response.status_code == 200
        assert response.content_type == 'application/json'
        assert "access_token" in response.json
    app.db.find_by_username.assert_called_once_with(username)

def test_login_invalid_credentials(client, app): # Use client and app fixtures
    """Test login with incorrect password."""
    username = "testuser"
    password = "testpassword"
    wrong_password = "wrongpassword"
    hashed_password = generate_password_hash(password)

    app.db.find_by_username.return_value = {
        "username": username,
        "password": hashed_password
    }

    with patch('werkzeug.security.check_password_hash', return_value=False):
        response = client.post("/api/login", json={"username": username, "password": wrong_password})
        
        assert response.status_code == 401
        assert response.content_type == 'application/json'
        assert "error" in response.json
        assert response.json["error"] == "Λανθασμένο όνομα χρήστη ή κωδικός" # Harmonize message
    app.db.find_by_username.assert_called_once_with(username)

def test_login_user_not_found(client, app): # Use client and app fixtures
    """Test login with a user that does not exist."""
    app.db.find_by_username.return_value = None
    response = client.post("/api/login", json={"username": "nonexistent", "password": "password"})
    assert response.status_code == 401
    assert response.content_type == 'application/json'
    assert "error" in response.json
    assert response.json["error"] == "Λανθασμένο όνομα χρήστη ή κωδικός" # Harmonize message
    app.db.find_by_username.assert_called_once_with("nonexistent")
