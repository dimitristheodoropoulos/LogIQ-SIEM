from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import json
import os

from werkzeug.security import generate_password_hash # Import for hashing passwords
from flask_jwt_extended import create_access_token # Import for token creation

# Removed local mock_db_instance, mock_mongo_db_instance, mock_report_generator, and app fixtures
# as they are now provided by conftest.py

# The 'app', 'client', 'mock_sqlite_db_instance', and 'mock_report_generator'
# fixtures will be automatically discovered from conftest.py.
# Ensure your conftest.py has these fixtures and correctly configures app.db.

def test_register_success(client, app):
    """Test successful user registration."""
    # Ensure app.db is set to the mock provided by conftest.py
    # (conftest.py's `app` fixture should handle this)
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

def test_register_existing_user(client, app):
    """Test registration of an existing user."""
    # Ensure app.db is set to the mock provided by conftest.py
    app.db.find_by_username.return_value = {"username": "existinguser", "password": generate_password_hash("password123")} # User exists
    
    response = client.post("/api/register", json={"username": "existinguser", "password": "password123"})
    
    assert response.status_code == 409 # Expecting 409 Conflict
    assert response.content_type == 'application/json'
    assert "error" in response.json
    assert response.json["error"] == "Το όνομα χρήστη υπάρχει ήδη" # Harmonize message
    app.db.find_by_username.assert_called_once_with("existinguser")
    app.db.insert_user.assert_not_called() # Should not try to insert

def test_login_and_add_event(client, app):
    """Test user login and then adding a security event."""
    username = "testuser"
    password = "testpassword"
    hashed_password = generate_password_hash(password)

    app.db.find_by_username.return_value = {
        "username": username,
        "password": hashed_password
    }
    
    with patch('werkzeug.security.check_password_hash', return_value=True):
        login_response = client.post("/api/login", json={"username": username, "password": password})
        assert login_response.status_code == 200
        access_token = login_response.json["access_token"]

    event_data = {"timestamp": "2023-01-01T12:00:00Z", "hostname": "test", "event_type": "test_event", "message": "test message"}
    headers = {"Authorization": f"Bearer {access_token}"}
    app.db.add_event.return_value = 1 # Simulate successful addition
    
    event_response = client.post("/api/events", json=[event_data], headers=headers)
    assert event_response.status_code == 201
    assert "events" in event_response.json
    assert len(event_response.json["events"]) == 1
    app.db.add_event.assert_called_once_with(event_data)

def test_report_with_token(client, app):
    """Test generating a report with a valid token."""
    mock_events = [ # Define mock events for the report
        {"timestamp": "2023-01-01T12:00:00Z", "message": "User logged in", "event_type": "login_success", "details": None},
    ]
    app.db.get_all_events.return_value = mock_events
    app.report_generator.generate_summary.return_value = {"total_events": 1, "time_window": "1h", "summary_data": "mock summary"}

    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}
    
    response = client.post("/api/report", json={"time_window": "1h"}, headers=headers)
    assert response.status_code == 200
    assert "summary" in response.json
    assert response.json["summary"]["total_events"] == 1
    app.db.get_all_events.assert_called_once()
    app.report_generator.generate_summary.assert_called_once_with("1h", mock_events) # Pass mock_events here


def test_export_json(client, app, tmp_path):
    """Test exporting logs to JSON via API."""
    mock_events = [
        {"event_type": "test_event", "timestamp": "2023-01-01T00:00:00Z", "message": "test", "details": None}
    ]
    app.db.get_all_events.return_value = mock_events
    
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}

    # Patch the export_logs_function from logiq.api.routes
    temp_file_path = tmp_path / "temp_export.json"
    with patch('logiq.api.routes.export_logs_function', return_value=str(temp_file_path)) as mock_export_logs:
        with patch('os.path.exists', return_value=True):
            mock_file_content = json.dumps(mock_events).encode('utf-8')
            temp_file_path.write_bytes(mock_file_content)
            
            response = client.get("/api/export?format=json", headers=headers)
                
            assert response.status_code == 200
            assert response.mimetype == 'application/json'
            assert json.loads(response.data) == mock_events
            app.db.get_all_events.assert_called_once()
            mock_export_logs.assert_called_once()
            args, kwargs = mock_export_logs.call_args
            assert args[0] == mock_events
            assert args[1] == "json"
            assert args[2].startswith("temp_export_") # Dynamic filename from api/routes.py
            assert kwargs['directory'] == app.config['UPLOAD_FOLDER']


def test_export_csv(client, app, tmp_path):
    """Test exporting logs to CSV via API."""
    mock_events = [
        {"event_type": "test_event", "timestamp": "2023-01-01T00:00:00Z", "message": "test", "details": None}
    ]
    app.db.get_all_events.return_value = mock_events
    
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}

    # Patch the export_logs_function to return a dummy file path within tmp_path
    temp_file_path = tmp_path / "temp_export.csv"
    with patch('logiq.api.routes.export_logs_function', return_value=str(temp_file_path)) as mock_export_logs:
        with patch('os.path.exists', return_value=True):
            # Adjusted CSV content to reflect how 'details': None would appear in CSV
            csv_content = "event_type,timestamp,message,ip,process,details\r\ntest_event,2023-01-01T00:00:00Z,test,,,\r\n" # Added headers and empty columns for ip, process, details
            temp_file_path.write_bytes(csv_content.encode('utf-8'))
            
            response = client.get("/api/export?format=csv", headers=headers)
                
            assert response.status_code == 200
            assert response.mimetype == 'text/csv'
            assert response.data.decode('utf-8') == csv_content
            app.db.get_all_events.assert_called_once()
            mock_export_logs.assert_called_once()
            args, kwargs = mock_export_logs.call_args
            assert args[0] == mock_events
            assert args[1] == "csv"
            assert args[2].startswith("temp_export_") # Dynamic filename from api/routes.py
            assert kwargs['directory'] == app.config['UPLOAD_FOLDER']

