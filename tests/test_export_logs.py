from __future__ import annotations

import pytest
from unittest.mock import patch, mock_open, MagicMock
import os
import json
import csv
from datetime import datetime
from logiq.export_logs import export_logs 

@pytest.fixture
def mock_events_data():
    """Provides mock event data for export tests."""
    return [
        {"timestamp": datetime(2023, 1, 1, 10, 0, 0).isoformat(), "event_type": "login_success", "username": "user1", "ip": "192.168.1.1", "details": "Session started"},
        {"timestamp": datetime(2023, 1, 1, 10, 5, 0).isoformat(), "event_type": "login_failure", "username": "user2", "ip": "192.168.1.2", "details": "Wrong password"},
        {"timestamp": datetime(2023, 1, 1, 10, 10, 0).isoformat(), "event_type": "logout", "username": "user1", "ip": "192.168.1.1", "details": None}
    ]

def test_export_logs_to_json_success(mock_events_data, tmp_path):
    """Test successful export of logs to JSON."""
    # The expected file path will be within tmp_path
    expected_file_path = tmp_path / "events.json"
    
    # Patch builtins.open and json.dump
    with patch("builtins.open", mock_open()) as mocked_open, \
         patch("logiq.export_logs.json.dump") as mock_json_dump:
        
        # Call export_logs, passing tmp_path as the directory
        success = export_logs(mock_events_data, "json", directory=str(tmp_path)) 
        
        # Assert that the returned path is the absolute path to the expected file
        assert success == str(expected_file_path.resolve()) # Use .resolve() for absolute path
        
        # Assert that builtins.open was called with the correct absolute path
        mocked_open.assert_called_once_with(str(expected_file_path), "w", encoding="utf-8")
        # Assert that json.dump was called with the correct data and the file handle
        mock_json_dump.assert_called_once_with(mock_events_data, mocked_open(), indent=2, default=str)


def test_export_logs_to_csv_success(mock_events_data, tmp_path):
    """Test successful export of logs to CSV."""
    expected_file_path = tmp_path / "events.csv"
    
    with patch('pandas.DataFrame.to_csv') as mock_to_csv:
        success = export_logs(mock_events_data, "csv", directory=str(tmp_path))
        assert success == str(expected_file_path.resolve()) # Use .resolve() for absolute path
        mock_to_csv.assert_called_once()
        args, kwargs = mock_to_csv.call_args
        # Assert the full path passed to to_csv
        assert args[0] == str(expected_file_path)
        assert kwargs['index'] is False
        assert kwargs['encoding'] == 'utf-8'


def test_export_logs_unsupported_format(mock_events_data, tmp_path, caplog):
    """Test export with an unsupported format."""
    
    success = export_logs(mock_events_data, "txt", directory=str(tmp_path))
    assert success is None # Now expects None for failure
    
    assert "Unsupported format: txt" in caplog.text


def test_export_logs_empty_data(tmp_path, caplog):
    """Test exporting empty list of logs."""
    output_file_path_json = tmp_path / "empty.json"
    
    success = export_logs([], "json", directory=str(tmp_path))
    assert success is None # Now expects None for failure
    
    assert "Δεν υπάρχουν συμβάντα για εξαγωγή" in caplog.text
    
    # Assert that the file was NOT created if data is empty and export fails
    assert not output_file_path_json.exists()


def test_export_logs_io_error(mock_events_data, tmp_path, caplog):
    """Test handling of IOError during export."""
    # Patch builtins.open in the context of export_logs module
    with patch("logiq.export_logs.open", side_effect=IOError("Disk full")):
        success = export_logs(mock_events_data, "json", "error_file", directory=str(tmp_path))
        assert success is None # Now expects None for failure
        
        assert "Σφάλμα κατά την εξαγωγή σε JSON: Disk full" in caplog.text
