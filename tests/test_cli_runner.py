from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from io import StringIO
import sys
from datetime import datetime, timedelta
import logging # Import logging for caplog.set_level

from logiq.cli.runner import run_parse_logs, run_alerts, run_report, run_db_connection_test, run_cli_command
from logiq.db.db_sqlite import SQLiteDatabase
from logiq.db.db_mongo import MongoDB # Import MongoDB for mocking
from logiq.reports.report_generator import ReportGenerator # Import for type hinting and patching
from logiq.parsers.auth_parser import parse_auth_log # Import for type hinting and patching

from logiq.detectors.anomalies import AnomalyDetector
from logiq.detectors.brute_force import BruteForceDetector

@pytest.fixture
def mock_db_instance():
    """Mock database instance for CLI runner tests."""
    mock_db = MagicMock(spec=SQLiteDatabase)
    mock_db.add_event.return_value = 1
    mock_db.get_events.return_value = []
    mock_db.get_alerts.return_value = []
    mock_db.get_all_events.return_value = []
    mock_db.connect.return_value = None
    mock_db.create_tables.return_value = None
    mock_db.close.return_value = None # Ensure close is mocked
    mock_db.conn = MagicMock() # Ensure conn is a mock by default
    return mock_db

@pytest.fixture
def mock_mongo_db_instance():
    """Fixture to create a mock MongoDB instance."""
    mock_mongo = MagicMock(spec=MongoDB)
    mock_mongo.client = MagicMock()
    mock_mongo.db = MagicMock()
    mock_mongo.collection = MagicMock()
    mock_mongo.connect = MagicMock()
    mock_mongo.close = MagicMock()
    mock_mongo.create_tables = MagicMock()
    mock_mongo.insert_user = MagicMock()
    mock_mongo.find_by_username = MagicMock()
    mock_mongo.add_event = MagicMock()
    mock_mongo.get_events = MagicMock(return_value=[])
    mock_mongo.get_all_events = MagicMock(return_value=[])
    return mock_mongo


@pytest.fixture
def mock_config():
    """Mock configuration for CLI runner tests."""
    return {
        "LOG_FILE_PATH": "/var/log/auth.log",
        "DATABASE_TYPE": "sqlite", # Default to sqlite for most tests
        "DATABASE_URI": ":memory:",
        "ANOMALIES_THRESHOLD_FACTOR": 2,
        "ANOMALIES_TIME_WINDOW": 3600,
        "ANOMALIES_MIN_EVENTS_FOR_BASELINE": 5,
        "BRUTE_FORCE_THRESHOLD": 5,
        "BRUTE_FORCE_TIME_WINDOW": 300,
        "API_BASE_URL": "http://localhost:5000/api",
        "AUTH_USERNAME": "testuser",
        "AUTH_PASSWORD": "testpassword",
        "SECRET_KEY": "test-secret" # Essential for JWTManager
    }

@pytest.fixture
def mock_app_context(mock_db_instance, mock_mongo_db_instance, mock_config):
    """Mocks the Flask app context for CLI runner tests."""
    # Patch load_config to ensure it always returns a valid config dict
    with patch('logiq.main.load_config', return_value=mock_config):
        # Patch the database classes themselves within main.py's scope
        with patch('logiq.main.SQLiteDatabase', return_value=mock_db_instance), \
             patch('logiq.main.MongoDB', return_value=mock_mongo_db_instance):
            
            mock_app = MagicMock()
            mock_app.db = mock_db_instance # Ensure db is set to the mock
            mock_app.config = mock_config
            
            mock_anomaly_detector = MagicMock(spec=AnomalyDetector)
            mock_brute_force_detector = MagicMock(spec=BruteForceDetector)
            
            mock_anomaly_detector.detect.return_value = []
            mock_brute_force_detector.detect.return_value = []

            mock_app.detectors = [
                mock_anomaly_detector,
                mock_brute_force_detector
            ]

            mock_app.report_generator = MagicMock(spec=ReportGenerator)
            mock_app.report_generator.generate_summary.return_value = {"total_events": 1, "time_window": "24h"}

            # Patch create_app in logiq.main to return our mock_app
            with patch('logiq.main.create_app', return_value=mock_app):
                yield mock_app


def test_run_parse_logs_success(mock_app_context, mock_db_instance):
    """Test successful log parsing and insertion."""
    mock_events = [
        {"timestamp": datetime.utcnow().isoformat(), "hostname": "test", "event_type": "login_success", "message": "msg1"},
        {"timestamp": datetime.utcnow().isoformat(), "hostname": "test", "event_type": "login_fail", "message": "msg2"}
    ]
    # Patch the function where it's *imported and used* within logiq.cli.runner
    with patch('logiq.cli.runner.parse_auth_log', return_value=mock_events) as mock_parse_auth_log:
        with patch('sys.stdout', new_callable=StringIO) as captured_output:
            run_parse_logs(mock_app_context)
            mock_parse_auth_log.assert_called_once_with(mock_app_context.config.get('LOG_FILE_PATH'))
            assert mock_db_instance.add_event.call_count == len(mock_events)
            assert f"Εισήχθησαν {len(mock_events)} events στη βάση δεδομένων." in captured_output.getvalue()

def test_run_parse_logs_no_events(mock_app_context, mock_db_instance):
    """Test log parsing when no events are found."""
    with patch('logiq.cli.runner.parse_auth_log', return_value=[]) as mock_parse_auth_log:
        with patch('sys.stdout', new_callable=StringIO) as captured_output:
            run_parse_logs(mock_app_context)
            mock_parse_auth_log.assert_called_once_with(mock_app_context.config.get('LOG_FILE_PATH'))
            mock_db_instance.add_event.assert_not_called()
            assert "Δεν βρέθηκαν νέα events για εισαγωγή." in captured_output.getvalue()

def test_run_alerts_with_alerts(mock_app_context):
    """Test running alerts command when alerts are detected."""
    mock_app_context.db.get_all_events.return_value = [
        {"timestamp": datetime.utcnow().isoformat(), "event_type": "Failed login", "username": "baduser", "ip": "1.1.1.1", "message": "test"}
    ]
    mock_app_context.detectors[1].detect.return_value = [
        {"alert_type": "brute_force", "username": "baduser", "message": "Brute force detected for baduser"}
    ]
    
    with patch('sys.stdout', new_callable=StringIO) as captured_output:
        run_alerts(mock_app_context)
        assert "Ενεργές Ειδοποιήσεις:" in captured_output.getvalue()
        assert "Brute force detected for baduser" in captured_output.getvalue()

def test_run_alerts_no_alerts(mock_app_context):
    """Test running alerts command when no alerts are detected."""
    mock_app_context.db.get_all_events.return_value = []
    mock_app_context.detectors[0].detect.return_value = []
    mock_app_context.detectors[1].detect.return_value = []
    
    with patch('sys.stdout', new_callable=StringIO) as captured_output:
        run_alerts(mock_app_context)
        assert "Δεν βρέθηκαν ενεργές ειδοποιήσεις." in captured_output.getvalue()

def test_run_report_success(mock_app_context):
    """Test successful report generation."""
    mock_events_for_report = [
        {"timestamp": datetime.utcnow().isoformat(), "event_type": "login_success", "message": "msg1"}
    ]
    mock_app_context.db.get_all_events.return_value = mock_events_for_report
    
    # mock_app_context.report_generator is already mocked in the fixture
    # and its generate_summary return_value is set.

    with patch('sys.stdout', new_callable=StringIO) as captured_output:
        run_report(mock_app_context, "24h")
        
        mock_app_context.db.get_all_events.assert_called_once()
        # Assert that generate_summary was called with the correct time_window and events
        mock_app_context.report_generator.generate_summary.assert_called_once_with("24h", mock_events_for_report) 
        assert "Η αναφορά δημιουργήθηκε επιτυχώς." in captured_output.getvalue()
        assert "Σύνοψη αναφοράς:" in captured_output.getvalue()

def test_run_db_connection_success(mock_app_context):
    """Test successful database connection test."""
    with patch('sys.stdout', new_callable=StringIO) as captured_output:
        run_db_connection_test(mock_app_context)
        assert "Επιτυχής σύνδεση με τη βάση δεδομένων." in captured_output.getvalue()

def test_run_db_connection_failure_and_exit(mock_app_context, caplog):
    """Test database connection failure leading to exit."""
    # Ensure the mock_app_context.db.conn is actually None for this test
    mock_app_context.db.conn = None
    
    # Set the logging level to CRITICAL for the caplog fixture
    caplog.set_level(logging.CRITICAL)
    
    with pytest.raises(SystemExit) as excinfo:
        run_db_connection_test(mock_app_context)
    
    # Assert that the critical message is in the captured logs' message attribute
    found_log_message = False
    expected_message = "Κρίσιμο σφάλμα: Αδύνατη η σύνδεση με τη βάση δεδομένων: Η σύνδεση είναι None."
    for record in caplog.records:
        if record.levelname == 'CRITICAL' and expected_message in record.message:
            found_log_message = True
            break
    assert found_log_message
    assert excinfo.value.code == 1 # Assert that the exit code is 1

def test_run_cli_command_parse_logs(mock_app_context):
    """Test run_cli_command with 'parse-logs'."""
    with patch('logiq.cli.runner.run_parse_logs') as mock_run_parse_logs:
        run_cli_command(mock_app_context, 'parse-logs')
        mock_run_parse_logs.assert_called_once_with(mock_app_context)

def test_run_cli_command_alerts(mock_app_context):
    """Test run_cli_command with 'alerts'."""
    with patch('logiq.cli.runner.run_alerts') as mock_run_alerts:
        run_cli_command(mock_app_context, 'alerts')
        mock_run_alerts.assert_called_once_with(mock_app_context)

def test_run_cli_command_report_success(mock_app_context):
    """Test run_cli_command with 'report' and time window."""
    with patch('logiq.cli.runner.run_report') as mock_run_report:
        run_cli_command(mock_app_context, 'report', '24h')
        mock_run_report.assert_called_once_with(mock_app_context, '24h')

def test_run_cli_command_report_no_time_window(mock_app_context):
    """Test run_cli_command with 'report' but no time window."""
    with pytest.raises(SystemExit) as excinfo:
        with patch('sys.stdout', new_callable=StringIO) as captured_stdout: 
            run_cli_command(mock_app_context, 'report')
            assert "Error: --time-window is required for 'report' command." in captured_stdout.getvalue()
    assert excinfo.value.code == 1

def test_run_cli_command_db_test(mock_app_context):
    """Test run_cli_command with 'db-test'."""
    with patch('logiq.cli.runner.run_db_connection_test') as mock_run_db_test:
        run_cli_command(mock_app_context, 'db-test')
        mock_run_db_test.assert_called_once_with(mock_app_context)

def test_run_cli_command_unknown(mock_app_context):
    """Test run_cli_command with an unknown command."""
    with pytest.raises(SystemExit) as excinfo:
        with patch('sys.stdout', new_callable=StringIO) as captured_stdout: 
            run_cli_command(mock_app_context, 'unknown-command')
            assert "Unknown CLI command: unknown-command" in captured_stdout.getvalue()
    assert excinfo.value.code == 1
