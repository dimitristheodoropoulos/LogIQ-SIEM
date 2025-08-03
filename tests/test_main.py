from __future__ import annotations

import pytest
import sys
from unittest.mock import patch, MagicMock
from logiq.main import create_app, main, CustomFlask # Import create_app, main, CustomFlask
import argparse 
from werkzeug.exceptions import HTTPException
from flask_jwt_extended import JWTManager 

def test_create_app_success():
    """Test successful application creation."""
    config = {'TESTING': True, 'DATABASE_TYPE': 'sqlite', 'DATABASE_URI': ':memory:', 'SECRET_KEY': 'test-secret'}
    # Patch the SQLiteDatabase class methods directly and get the mock objects within logiq.main scope
    with patch('logiq.main.SQLiteDatabase.connect') as mock_connect, \
         patch('logiq.main.SQLiteDatabase.create_tables') as mock_create_tables, \
         patch('logiq.main.SQLiteDatabase.__init__', return_value=None), \
         patch('logiq.main.MongoDB.__init__', return_value=None), \
         patch('logiq.main.JWTManager'), \
         patch('logiq.main.api_blueprint'), \
         patch('logiq.main.AnomalyDetector'), \
         patch('logiq.main.BruteForceDetector'), \
         patch('logiq.main.ReportGenerator'), \
         patch('logiq.main.load_config', return_value=config): # Ensure load_config is patched
        
        app = create_app(config=config)
        assert isinstance(app, CustomFlask) # Assert it returns an instance of CustomFlask
        assert 'TESTING' in app.config
        mock_connect.assert_called_once()
        mock_create_tables.assert_called_once()

def test_create_app_db_connection_error():
    """Test that create_app returns None when DB connection fails."""
    config = {'TESTING': True, 'DATABASE_TYPE': 'sqlite', 'DATABASE_URI': ':memory:', 'SECRET_KEY': 'test-secret'}
    with patch('logiq.main.SQLiteDatabase.connect', side_effect=ConnectionError("Connection failed")) as mock_connect, \
         patch('logiq.main.SQLiteDatabase.__init__', return_value=None), \
         patch('logiq.main.MongoDB.__init__', return_value=None), \
         patch('logiq.main.JWTManager'), \
         patch('logiq.main.api_blueprint'), \
         patch('logiq.main.AnomalyDetector'), \
         patch('logiq.main.BruteForceDetector'), \
         patch('logiq.main.ReportGenerator'), \
         patch('logiq.main.load_config', return_value=config): # Ensure load_config is patched
        
        app = create_app(config=config)
        assert app is None # Assert it returns None on connection error
        mock_connect.assert_called_once()

def test_create_app_unsupported_db_type():
    """Test that create_app returns None for an unsupported database type."""
    config = {'DATABASE_TYPE': 'unsupported', 'DATABASE_URI': ':memory:', 'SECRET_KEY': 'test-secret'}
    with patch('logiq.main.load_config', return_value=config), \
         patch('logiq.main.JWTManager'), \
         patch('logiq.main.api_blueprint'), \
         patch('logiq.main.AnomalyDetector'), \
         patch('logiq.main.BruteForceDetector'), \
         patch('logiq.main.ReportGenerator'):
        app = create_app(config=config, db_type='unsupported')
        assert app is None

def test_main_cli_mode_success():
    """Test that main() calls the CLI runner for 'cli' mode."""
    with patch('sys.argv', ['main.py', '--mode', 'cli', '--cli-command', 'parse-logs']):
        mock_app = MagicMock(spec=CustomFlask)
        # Ensure mock_app has a 'db' attribute, as run_cli_command expects it
        mock_app.db = MagicMock() 
        mock_app.db.close = MagicMock() # Mock the close method expected in main()
        with patch('logiq.main.create_app', return_value=mock_app) as mock_create_app:
            with patch('logiq.cli.runner.run_cli_command') as mock_run_cli:
                try:
                    main()
                except SystemExit as e:
                    assert e.code == 0

                mock_create_app.assert_called_once()
                mock_run_cli.assert_called_once_with(mock_app, 'parse-logs', None)
                mock_app.db.close.assert_called_once() # Assert close is called

def test_main_cli_mode_create_app_failure():
    """Test that main() exits gracefully when create_app fails in 'cli' mode."""
    with patch('sys.argv', ['main.py', '--mode', 'cli', '--cli-command', 'parse-logs']):
        with patch('logiq.main.create_app', return_value=None):
            with pytest.raises(SystemExit) as excinfo:
                main()
            assert excinfo.value.code == 1

def test_main_flask_server_mode_success():
    """Test that main() runs the Flask app in 'server' mode."""
    with patch('sys.argv', ['main.py', '--mode', 'server']):
        mock_app = MagicMock(spec=CustomFlask)
        mock_app.run = MagicMock()
        with patch('logiq.main.create_app', return_value=mock_app) as mock_create_app:
            main()
            mock_create_app.assert_called_once()
            mock_app.run.assert_called_once_with(debug=True)

def test_main_flask_server_mode_create_app_failure():
    """Test that main() exits gracefully when create_app fails in 'server' mode."""
    with patch('sys.argv', ['main.py', '--mode', 'server']):
        with patch('logiq.main.create_app', return_value=None):
            with pytest.raises(SystemExit) as excinfo:
                main()
            assert excinfo.value.code == 1
