from __future__ import annotations
import pytest
from unittest.mock import patch, MagicMock
from main import create_app, main, CustomFlask

def test_main_flask_server_mode_success(client, app):
    """Test that main() runs the Flask app in 'server' mode."""
    # Patch των sys.argv για να προσομοιώσουμε την κλήση από το τερματικό
    with patch('sys.argv', ['main.py', '--mode', 'server']):
        mock_app = MagicMock(spec=CustomFlask)
        mock_app.run = MagicMock()
        
        with patch('main.create_app', return_value=mock_app) as mock_create_app:
            main()
            mock_create_app.assert_called_once()
            
            # Έλεγχος ότι η εφαρμογή ξεκίνησε με σωστά ορίσματα
            args, kwargs = mock_app.run.call_args
            assert kwargs['debug'] is True
            assert 'host' in kwargs
            assert 'port' in kwargs

def test_main_cli_mode_success(client, app):
    """Test that main() calls the CLI runner for 'cli' mode."""
    with patch('sys.argv', ['main.py', '--mode', 'cli', '--cli-command', 'parse-logs']):
        mock_app = MagicMock(spec=CustomFlask)
        mock_app.db = MagicMock()
        
        # Προσθήκη του config attribute για να αποφευχθεί το AttributeError
        mock_app.config = MagicMock()
        mock_app.config.get.side_effect = lambda key, default=None: {'LOG_FILE_PATH': '/tmp/test.log'}.get(key, default)
        
        with patch('main.create_app', return_value=mock_app) as mock_create_app:
            # ΔΙΟΡΘΩΣΗ: Κάνουμε patch εκεί που ΚΑΛΕΙΤΑΙ η συνάρτηση (στο main)
            with patch('main.run_cli_command') as mock_run_cli:
                with pytest.raises(SystemExit) as e:
                    main()
                assert e.value.code == 0
                mock_create_app.assert_called_once()
                mock_run_cli.assert_called_once()