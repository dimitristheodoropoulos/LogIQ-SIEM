import pytest
from unittest.mock import patch, mock_open
from utils.config import load_config
import json
import os

def test_load_config_success(api_client, app, tmp_path):
    """Test successful loading of a valid JSON configuration file."""
    config_content = {"database": {"uri": "test_uri"}, "app_name": "logiq_test"}
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config_content))
    
    loaded_config = load_config(str(config_file))
    assert loaded_config == config_content

def test_load_config_file_not_found(api_client, app):
    """Test that load_config handles FileNotFoundError gracefully."""
    with patch('os.path.exists', return_value=False):
        loaded_config = load_config("non_existent_file.json")
    assert loaded_config is None

def test_load_config_invalid_json(api_client, app, tmp_path):
    """Test that load_config handles syntax errors correctly."""
    invalid_content = "{database: [unclosed_bracket_invalid_syntax"
    config_file = tmp_path / "invalid.json"
    config_file.write_text(invalid_content)
    
    loaded_config = load_config(str(config_file))
    assert loaded_config is None

def test_load_config_default_path(api_client, app):
    """Test that the function uses the default path if no path is provided."""
    config_content = {"database": {"uri": "default_uri"}}
    with patch('builtins.open', mock_open(read_data=json.dumps(config_content))) as mock_file:
        with patch('os.path.exists', return_value=True):
            loaded_config = load_config()
            
    mock_file.assert_called_once_with('config.yaml', 'r')