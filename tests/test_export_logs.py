from __future__ import annotations

import pytest
from unittest.mock import patch, mock_open, MagicMock
import os
import json
import csv
from datetime import datetime, timezone
from export_logs import export_logs 

@pytest.fixture
def mock_events_data():
    """Provides mock event data for export tests."""
    return [
        {"timestamp": datetime(2023, 1, 1, 10, 0, 0).isoformat(), "event_type": "login_success", "username": "user1", "ip": "192.168.1.1", "details": "Session started"},
        {"timestamp": datetime(2023, 1, 1, 10, 5, 0).isoformat(), "event_type": "login_failure", "username": "user2", "ip": "192.168.1.2", "details": "Wrong password"},
        {"timestamp": datetime(2023, 1, 1, 10, 10, 0).isoformat(), "event_type": "logout", "username": "user1", "ip": "192.168.1.1", "details": None}
    ]

def test_export_logs_to_json_success(api_client, app, tmp_path, mock_events_data):
    """Test successful export of logs to JSON."""
    expected_file_path = tmp_path / "events.json"
    
    with patch("builtins.open", mock_open()) as mocked_open, \
         patch("export_logs.json.dump") as mock_json_dump:
        
        success = export_logs(mock_events_data, "json", directory=str(tmp_path)) 
        assert success == str(expected_file_path.resolve())
        mocked_open.assert_called_once_with(str(expected_file_path), "w", encoding="utf-8")
        mock_json_dump.assert_called_once_with(mock_events_data, mocked_open(), indent=2, default=str)


def test_export_logs_to_csv_success(api_client, app, tmp_path, mock_events_data):
    """Test successful export of logs to CSV."""
    expected_file_path = tmp_path / "events.csv"
    
    with patch('pandas.DataFrame.to_csv') as mock_to_csv:
        success = export_logs(mock_events_data, "csv", directory=str(tmp_path))
        assert success == str(expected_file_path.resolve())
        mock_to_csv.assert_called_once()
        args, kwargs = mock_to_csv.call_args
        assert args[0] == str(expected_file_path)
        assert kwargs['index'] is False
        assert kwargs['encoding'] == 'utf-8'


def test_export_logs_unsupported_format(api_client, app, tmp_path, mock_events_data, caplog):
    """Test export with an unsupported format."""
    success = export_logs(mock_events_data, "txt", directory=str(tmp_path))
    assert success is None
    assert "Unsupported format: txt" in caplog.text


def test_export_logs_empty_data(api_client, app, tmp_path, caplog):
    """Test exporting empty list of logs."""
    output_file_path_json = tmp_path / "empty.json"
    success = export_logs([], "json", directory=str(tmp_path))
    assert success is None
    assert "Δεν υπάρχουν συμβάντα για εξαγωγή" in caplog.text
    assert not output_file_path_json.exists()


def test_export_logs_io_error(api_client, app, tmp_path, mock_events_data, caplog):
    """Test handling of IOError during export."""
    with patch("export_logs.open", side_effect=IOError("Disk full")):
        success = export_logs(mock_events_data, "json", "error_file", directory=str(tmp_path))
        assert success is None
        assert "Σφάλμα κατά την εξαγωγή σε JSON: Disk full" in caplog.text