from __future__ import annotations

import json
from unittest.mock import patch, MagicMock
from typing import cast, Union
from datetime import datetime, timedelta

import pytest
from flask import Flask, send_file
from flask_jwt_extended import create_access_token

# Assuming the fixtures for `app`, `client`, `mock_db_instance`, and `mock_report_generator`
# are available from `conftest.py`.

# --- Test Cases for Report Export ---

def test_report_export_json_success(client, mock_sqlite_db_instance, mock_report_generator, app, tmp_path):
    """
    Test successful generation and export of a report in JSON format.
    """
    # Ensure app.db is set to the mock_sqlite_db_instance for this test
    app.db = mock_sqlite_db_instance

    # Mock data that the database would return
    mock_sqlite_db_instance.get_all_events.return_value = [
        {"timestamp": "2023-01-01T12:00:00Z", "message": "User logged in", "event_type": "login_success", "details": None},
        {"timestamp": "2023-01-01T12:01:00Z", "message": "User failed login", "event_type": "login_fail", "details": None},
    ]

    # Mock the report generator's summary output
    mock_report_generator.generate_summary.return_value = {
        "total_events": 2,
        "time_window": "1h",
        "summary_data": "Mock summary for JSON report."
    }

    # Generate a valid JWT token
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}

    # Define a temporary file path for the mocked report output
    temp_report_file = tmp_path / "report_summary.json"

    # Patch the internal helper function _export_report_summary in logiq.api.routes
    with patch('logiq.api.routes._export_report_summary', return_value=str(temp_report_file)) as mock_export_report_summary:
        # Simulate writing content to the dummy file for Flask's send_file to read
        report_content = {
            "summary": mock_report_generator.generate_summary.return_value,
            "events_data": mock_sqlite_db_instance.get_all_events.return_value
        }
        temp_report_file.write_text(json.dumps(report_content))

        # Change POST to GET and adjust the URL to the new /api/report/export endpoint
        response = client.get("/api/report/export?format=json&time_window=1h", headers=headers)

        assert response.status_code == 200
        assert response.mimetype == 'application/json'
        assert json.loads(response.data) == report_content

        # Verify that the correct functions were called
        mock_sqlite_db_instance.get_all_events.assert_called_once()
        mock_report_generator.generate_summary.assert_called_once_with(
            "1h", mock_sqlite_db_instance.get_all_events.return_value
        )
        mock_export_report_summary.assert_called_once()
        # Check arguments passed to _export_report_summary
        args, kwargs = mock_export_report_summary.call_args
        assert args[0] == report_content # Should be the full_report_data dictionary
        assert args[1] == "json"
        assert args[2].startswith("report_summary_") # Dynamic filename prefix
        assert kwargs['directory'] == app.config['UPLOAD_FOLDER']


def test_report_export_pdf_success(client, mock_sqlite_db_instance, mock_report_generator, app, tmp_path):
    """
    Test successful generation and export of a report in PDF format.
    """
    # Ensure app.db is set to the mock_sqlite_db_instance for this test
    app.db = mock_sqlite_db_instance

    mock_sqlite_db_instance.get_all_events.return_value = [
        {"timestamp": "2023-01-01T12:00:00Z", "message": "PDF Test Event", "event_type": "test_pdf", "details": None},
    ]

    mock_report_generator.generate_summary.return_value = {
        "total_events": 1,
        "time_window": "24h",
        "summary_data": "Mock summary for PDF report."
    }

    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}

    temp_report_file = tmp_path / "report_summary.pdf"

    # Patch the internal helper function _export_report_summary in logiq.api.routes
    with patch('logiq.api.routes._export_report_summary', return_value=str(temp_report_file)) as mock_export_report_summary:
        # Simulate writing dummy PDF content
        temp_report_file.write_bytes(b"%PDF-1.4\n%%EOF") # Minimal valid PDF header

        # Change POST to GET and adjust the URL to the new /api/report/export endpoint
        response = client.get("/api/report/export?format=pdf&time_window=24h", headers=headers)

        assert response.status_code == 200
        assert response.mimetype == 'application/pdf'
        assert response.data == b"%PDF-1.4\n%%EOF" # Verify content

        mock_sqlite_db_instance.get_all_events.assert_called_once()
        mock_report_generator.generate_summary.assert_called_once()
        mock_export_report_summary.assert_called_once()
        args, kwargs = mock_export_report_summary.call_args
        assert args[1] == "pdf"
        assert args[2].startswith("report_summary_") # Dynamic filename prefix
        assert kwargs['directory'] == app.config['UPLOAD_FOLDER']


def test_report_export_unsupported_format(client, app):
    """
    Test report export with an unsupported format.
    """
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}

    # Change POST to GET and adjust the URL to the new /api/report/export endpoint
    response = client.get("/api/report/export?format=csv&time_window=1h", headers=headers)

    assert response.status_code == 400
    assert response.content_type == 'application/json'
    assert "error" in response.json
    # Updated expected error message to match the new route's response
    assert "Unsupported report format: csv. Supported formats are 'json', 'pdf'." in response.json["error"]

def test_report_export_invalid_time_window(client, app):
    """
    Test report export with an invalid time window parameter.
    """
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}

    # Change POST to GET and adjust the URL to the new /api/report/export endpoint
    response = client.get("/api/report/export?format=json&time_window=invalid", headers=headers)

    assert response.status_code == 400
    assert response.content_type == 'application/json'
    assert "error" in response.json
    # The error message for invalid time_window is handled by the route itself before report_generator
    assert "Invalid 'time_window' value. Numeric part is invalid." in response.json["error"]


def test_report_export_missing_time_window(client, app):
    """
    Test report export when the time_window parameter is missing.
    """
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}

    # Change POST to GET and adjust the URL to the new /api/report/export endpoint
    response = client.get("/api/report/export?format=json", headers=headers)

    assert response.status_code == 400
    assert response.content_type == 'application/json'
    assert "error" in response.json
    # Updated expected error message to match the new route's response
    assert "Missing 'time_window' parameter" in response.json["error"]

def test_report_export_unauthorized(client):
    """
    Test report export without a valid JWT token.
    """
    # Change POST to GET and adjust the URL to the new /api/report/export endpoint
    response = client.get("/api/report/export?format=json&time_window=1h")

    assert response.status_code == 401
    assert response.content_type == 'application/json'
    assert b"Missing JWT" in response.data
