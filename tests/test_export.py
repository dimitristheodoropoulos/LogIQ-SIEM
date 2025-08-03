from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
import json
import os
from flask_jwt_extended import create_access_token # Import create_access_token

# The 'app', 'client', 'mock_sqlite_db_instance' (and 'mock_mongo_db_instance' if needed)
# fixtures will be automatically discovered from conftest.py.

# Note: The 'app' fixture in conftest.py will set app.db to either mock_sqlite_db_instance
# or mock_mongo_db_instance based on config['DATABASE_TYPE'].
# For these tests, we'll primarily use mock_sqlite_db_instance as the default.

def test_export_json(client, app, tmp_path): # Removed mock_sqlite_db_instance from args, use app.db directly
    """Test exporting events to JSON via API."""
    # Ensure app.db is set to the mock_sqlite_db_instance for this test
    # This is handled by the app fixture in conftest.py based on DATABASE_TYPE in config.
    # We can assume app.db is the correct mock here.

    mock_events = [
        {"event_type": "test_event", "timestamp": "2023-01-01T00:00:00Z", "message": "test", "details": None, "ip": None, "process": None}
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
            expected_data = mock_events # The API should return the events as JSON
            assert json.loads(response.data) == expected_data
            app.db.get_all_events.assert_called_once()
            mock_export_logs.assert_called_once()
            args, kwargs = mock_export_logs.call_args
            assert args[0] == mock_events
            assert args[1] == "json"
            assert args[2].startswith("temp_export_") # Dynamic filename
            assert kwargs['directory'] == app.config['UPLOAD_FOLDER'] # Use app.config['UPLOAD_FOLDER']

def test_export_csv(client, app, tmp_path): # Removed mock_sqlite_db_instance from args, use app.db directly
    """Test exporting events to CSV via API."""
    # Ensure app.db is set to the mock_sqlite_db_instance for this test
    # This is handled by the app fixture in conftest.py based on DATABASE_TYPE in config.

    mock_events = [
        {"event_type": "test_event", "timestamp": "2023-01-01T00:00:00Z", "message": "test", "details": None, "ip": None, "process": None}
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
            # It usually results in an empty string or just a comma for that column.
            # Ensure the CSV content matches what your export_logs.py would produce
            csv_content = "event_type,timestamp,message,details,ip,process\r\ntest_event,2023-01-01T00:00:00Z,test,,,\r\n"
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
            assert args[2].startswith("temp_export_") # Dynamic filename
            assert kwargs['directory'] == app.config['UPLOAD_FOLDER'] # Use app.config['UPLOAD_FOLDER']