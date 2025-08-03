from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import json
from werkzeug.security import generate_password_hash
from flask_jwt_extended import create_access_token # Import create_access_token

# The 'app', 'client', 'mock_sqlite_db_instance', 'mock_mongo_db_instance'
# fixtures will be automatically discovered from conftest.py.

def test_index_route(client):
    """Test the base index route."""
    response = client.get("/")
    assert response.status_code == 200
    assert "Welcome to the Logiq SIEM API!" in response.json["message"]

def test_register_user_success(client, app):
    """Test successful user registration."""
    # Ensure find_by_username returns None initially to simulate user not existing
    app.db.find_by_username.return_value = None
    
    response = client.post("/api/register", json={"username": "testuser", "password": "password123"})
    assert response.status_code == 201
    assert "Επιτυχής εγγραφή χρήστη" in response.json["message"]
    assert "user_id" in response.json
    
    # Assert that find_by_username was called to check for existing user
    app.db.find_by_username.assert_called_once_with("testuser")
    # Assert that insert_user was called
    app.db.insert_user.assert_called_once()
    args, kwargs = app.db.insert_user.call_args
    assert args[0] == "testuser"
    assert isinstance(args[1], str) # Check if password is hashed

def test_register_user_duplicate(client, app):
    """Test registering a user that already exists."""
    # Simulate user already existing
    app.db.find_by_username.return_value = {"username": "existinguser", "password": "hashedpassword"}
    
    response = client.post("/api/register", json={"username": "existinguser", "password": "password123"})
    assert response.status_code == 409 # Conflict
    assert "Το όνομα χρήστη υπάρχει ήδη" in response.json["error"]
    
    app.db.find_by_username.assert_called_once_with("existinguser")
    app.db.insert_user.assert_not_called() # Should not try to insert

def test_register_user_invalid_data(client):
    """Test user registration with invalid data."""
    response = client.post("/api/register", json={"username": "ab", "password": "123"}) # Too short
    assert response.status_code == 422 # Unprocessable Entity
    assert "minLength" in response.json["error"] # Schema validation error message

def test_login_user_success(client, app):
    """Test successful user login."""
    hashed_password = generate_password_hash("password123")
    app.db.find_by_username.return_value = {"username": "testuser", "password": hashed_password}
    
    response = client.post("/api/login", json={"username": "testuser", "password": "password123"})
    assert response.status_code == 200
    assert "access_token" in response.json
    app.db.find_by_username.assert_called_once_with("testuser")

def test_login_user_invalid_credentials(client, app):
    """Test login with incorrect password."""
    hashed_password = generate_password_hash("correctpassword")
    app.db.find_by_username.return_value = {"username": "testuser", "password": hashed_password}
    
    response = client.post("/api/login", json={"username": "testuser", "password": "wrongpassword"})
    assert response.status_code == 401
    assert "Λανθασμένο όνομα χρήστη ή κωδικός" in response.json["error"]

def test_login_user_not_found(client, app):
    """Test login with a non-existent user."""
    app.db.find_by_username.return_value = None
    
    response = client.post("/api/login", json={"username": "nonexistent", "password": "password123"})
    assert response.status_code == 401
    assert "Λανθασμένο όνομα χρήστη ή κωδικός" in response.json["error"]
    app.db.find_by_username.assert_called_once_with("nonexistent")

def test_add_security_event_success(client, app):
    """Test adding a security event with valid data and authentication."""
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}
    
    event_data = [{
        "timestamp": "2023-01-01T12:00:00Z",
        "hostname": "host1",
        "event_type": "login_success",
        "message": "User logged in",
        "ip": "192.168.1.1",
        "details": {"user": "admin"}
    }]
    
    app.db.add_event.return_value = "event_id_123" # Mock return value for add_event
    
    response = client.post("/api/events", json=event_data, headers=headers)
    assert response.status_code == 201
    assert "Events added successfully" in response.json["message"]
    assert len(response.json["events"]) == 1
    assert response.json["events"][0]["id"] == "event_id_123"
    
    app.db.add_event.assert_called_once()
    args, kwargs = app.db.add_event.call_args
    assert args[0]["hostname"] == "host1"
    assert args[0]["event_type"] == "login_success"

def test_add_security_event_invalid_data(client, app):
    """Test adding a security event with invalid data format."""
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}
    
    invalid_event_data = [{
        "timestamp": "invalid-date-format", # Invalid timestamp
        "hostname": "host1",
        "event_type": "login_success",
        "message": "User logged in"
    }]
    
    response = client.post("/api/events", json=invalid_event_data, headers=headers)
    assert response.status_code == 422 # Unprocessable Entity due to schema validation
    assert "Invalid event data" in response.json["error"]
    app.db.add_event.assert_not_called()

def test_add_security_event_invalid_token(client):
    """Test adding a security event with an invalid JWT token."""
    headers = {"Authorization": "Bearer invalid.jwt.token"}
    event_data = [{
        "timestamp": "2023-01-01T12:00:00Z",
        "hostname": "host1",
        "event_type": "login_success",
        "message": "User logged in"
    }]
    
    response = client.post("/api/events", json=event_data, headers=headers)
    assert response.status_code == 401 # Unauthorized
    assert b"Invalid JWT" in response.data

def test_add_security_event_missing_token(client):
    """Test adding a security event without any JWT token."""
    event_data = [{
        "timestamp": "2023-01-01T12:00:00Z",
        "hostname": "host1",
        "event_type": "login_success",
        "message": "User logged in"
    }]
    
    response = client.post("/api/events", json=event_data)
    assert response.status_code == 401 # Unauthorized
    assert b"Missing Authorization Header" in response.data

def test_get_alerts_success(client, app):
    """Test retrieving alerts with valid parameters."""
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Mock get_events to return some data for detectors
    mock_events = [
        {"timestamp": (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z", "hostname": "h1", "event_type": "login_fail", "message": "fail", "ip": "1.1.1.1"},
        {"timestamp": datetime.utcnow().isoformat() + "Z", "hostname": "h1", "event_type": "login_fail", "message": "fail", "ip": "1.1.1.1"}
    ]
    app.db.get_events.return_value = mock_events
    
    # Mock detector.detect to return some alerts
    app.detectors[0].detect.return_value = [{"alert_type": "anomaly", "message": "Anomaly detected"}]
    app.detectors[1].detect.return_value = [{"alert_type": "brute_force", "message": "Brute force detected"}]

    response = client.get("/api/alerts?threshold=1&time_window=24h", headers=headers)
    assert response.status_code == 200
    assert "alerts" in response.json
    assert len(response.json["alerts"]) > 0
    app.db.get_events.assert_called_once()
    app.detectors[0].detect.assert_called_once_with(mock_events)
    app.detectors[1].detect.assert_called_once_with(mock_events)


def test_get_alerts_missing_parameters(client, app):
    """Test retrieving alerts with missing parameters."""
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}
    
    response = client.get("/api/alerts", headers=headers) # Missing threshold and time_window
    assert response.status_code == 400
    assert "Missing 'threshold' parameter" in response.json["error"]

    response = client.get("/api/alerts?threshold=1", headers=headers) # Missing time_window
    assert response.status_code == 400
    assert "Missing 'time_window' parameter" in response.json["error"]

def test_get_alerts_invalid_parameters(client, app):
    """Test retrieving alerts with invalid parameters."""
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}
    
    response = client.get("/api/alerts?threshold=abc&time_window=24h", headers=headers) # Invalid threshold
    assert response.status_code == 400
    assert "Invalid 'threshold' parameter" in response.json["error"]

    response = client.get("/api/alerts?threshold=1&time_window=24x", headers=headers) # Invalid time_window unit
    assert response.status_code == 400
    assert "Invalid 'time_window' unit" in response.json["error"]

    response = client.get("/api/alerts?threshold=1&time_window=abc", headers=headers) # Invalid time_window value
    assert response.status_code == 400
    assert "Invalid 'time_window' value" in response.json["error"]


def test_generate_report_success(client, app):
    """Test successful report generation."""
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}
    
    mock_events = [
        {"timestamp": datetime.utcnow().isoformat() + "Z", "hostname": "h1", "event_type": "login_success", "message": "msg1"},
        {"timestamp": (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z", "hostname": "h2", "event_type": "login_fail", "message": "msg2"}
    ]
    app.db.get_all_events.return_value = mock_events
    app.report_generator.generate_summary.return_value = {"total_events": 2, "time_window": "24h", "summary_data": "mock summary"}

    response = client.post("/api/report", json={"time_window": "24h"}, headers=headers)
    assert response.status_code == 200
    assert "summary" in response.json
    assert response.json["summary"]["total_events"] == 2
    app.db.get_all_events.assert_called_once()
    app.report_generator.generate_summary.assert_called_once_with("24h", mock_events)


def test_generate_report_missing_time_window(client, app):
    """Test report generation with missing time window."""
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}
    
    response = client.post("/api/report", json={}, headers=headers)
    assert response.status_code == 400
    assert "Missing 'time_window' parameter" in response.json["error"]


def test_export_json_success(client, app, tmp_path):
    """Test exporting events to JSON via API."""
    mock_events = [
        {"event_type": "test_event", "timestamp": "2023-01-01T00:00:00Z", "message": "test", "details": None, "_id": "some_id"}
    ]
    app.db.get_all_events.return_value = mock_events
    
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}

    # Patch the export_logs_function from logiq.api.routes
    temp_file_path = tmp_path / "temp_export.json"
    with patch('logiq.api.routes.export_logs_function', return_value=str(temp_file_path)) as mock_export_logs:
        with patch('os.path.exists', return_value=True):
            # Simulate writing content to the dummy file for send_file to read
            # The _id field is typically removed during serialization for export, so the comparison should reflect that.
            mock_file_content = json.dumps([{"event_type": "test_event", "timestamp": "2023-01-01T00:00:00Z", "message": "test", "details": None}]).encode('utf-8')
            temp_file_path.write_bytes(mock_file_content) # Use write_bytes for binary content
            
            response = client.get("/api/export?format=json", headers=headers)
            
            assert response.status_code == 200
            assert response.mimetype == 'application/json'
            expected_data = [{"event_type": "test_event", "timestamp": "2023-01-01T00:00:00Z", "message": "test", "details": None}]
            assert json.loads(response.data) == expected_data
            app.db.get_all_events.assert_called_once()
            mock_export_logs.assert_called_once()
            args, kwargs = mock_export_logs.call_args
            assert args[0] == mock_events # The data passed to export_logs_function should still contain the _id
            assert args[1] == "json"
            assert args[2].startswith("temp_export_") # Dynamic filename
            assert kwargs['directory'] == str(tmp_path) # Use str(tmp_path) for comparison

def test_export_csv_success(client, app, tmp_path):
    """Test exporting events to CSV via API."""
    mock_events = [
        {"event_type": "test_event", "timestamp": "2023-01-01T00:00:00Z", "message": "test", "details": None, "_id": "some_id"}
    ]
    app.db.get_all_events.return_value = mock_events
    
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}

    # Patch the export_logs_function from logiq.api.routes
    temp_file_path = tmp_path / "temp_export.csv"
    with patch('logiq.api.routes.export_logs_function', return_value=str(temp_file_path)) as mock_export_logs:
        with patch('os.path.exists', return_value=True):
            # Adjusted CSV content to reflect how 'details': None would appear in CSV
            csv_content = "event_type,timestamp,message\r\ntest_event,2023-01-01T00:00:00Z,test"
            temp_file_path.write_bytes(csv_content.encode('utf-8'))
            
            response = client.get("/api/export?format=csv", headers=headers)
                
            assert response.status_code == 200
            assert response.mimetype == 'text/csv'
            assert response.data.decode('utf-8') == csv_content
            app.db.get_all_events.assert_called_once()
            mock_export_logs.assert_called_once()
            args, kwargs = mock_export_logs.call_args
            assert args[0] == mock_events # The data passed to export_logs_function should still contain the _id
            assert args[1] == "csv"
            assert args[2].startswith("temp_export_") # Dynamic filename
            assert kwargs['directory'] == str(tmp_path) # Use str(tmp_path) for comparison

def test_export_unsupported_format(client, app):
    """Test exporting with an unsupported format."""
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}
    
    response = client.get("/api/export?format=pdf", headers=headers)
    assert response.status_code == 400
    assert "Unsupported format: pdf" in response.json["error"]

def test_export_unauthorized(client):
    """Test exporting without authentication."""
    response = client.get("/api/export?format=json")
    assert response.status_code == 401
    assert b"Missing Authorization Header" in response.data

def test_report_export_invalid_time_window(client, app):
    """Test report export with an invalid time window parameter."""
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # The route expects a POST request with JSON body
    response = client.post("/api/report", json={"time_window": "invalid_window"}, headers=headers)
    assert response.status_code == 400
    assert "Invalid 'time_window' format" in response.json["error"]

