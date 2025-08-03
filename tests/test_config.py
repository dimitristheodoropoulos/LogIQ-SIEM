import pytest
from unittest.mock import patch, mock_open
from utils.config import load_config
import json
import os

def test_load_config_success(tmp_path):
    """Test successful loading of a valid JSON configuration file."""
    # Create a temporary config file for the test
    config_content = {"database": {"uri": "test_uri"}, "app_name": "logiq_test"}
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config_content))
    
    # Call the function with the path to the temporary file
    loaded_config = load_config(str(config_file))
    
    # Assert that the loaded dictionary matches the expected content
    assert loaded_config == config_content

def test_load_config_file_not_found():
    """Test that load_config handles FileNotFoundError gracefully."""
    # Use a non-existent path
    with patch('os.path.exists', return_value=False):
        loaded_config = load_config("non_existent_file.json")
    
    # Assert that the function returns None for a missing file
    assert loaded_config is None

def test_load_config_invalid_json(tmp_path):
    """Test that load_config handles a JSONDecodeError."""
    # Create a temporary file with invalid JSON content
    invalid_content = "{'database': 'test_uri', 'app_name': 'logiq_test'}" # Using single quotes is invalid JSON
    config_file = tmp_path / "invalid.json"
    config_file.write_text(invalid_content)
    
    # Call the function with the invalid file
    loaded_config = load_config(str(config_file))
    
    # Assert that the function returns None for invalid JSON
    assert loaded_config is None

def test_load_config_default_path():
    """Test that the function uses the default path if no path is provided."""
    # Mock the default file path and its content
    config_content = {"database": {"uri": "default_uri"}}
    with patch('builtins.open', mock_open(read_data=json.dumps(config_content))) as mock_file:
        with patch('os.path.exists', return_value=True):
            loaded_config = load_config()
            
    # Assert that the default path was opened
    mock_file.assert_called_once_with('config/config.json', 'r')
    # Assert that the content was loaded correctly
    assert loaded_config == config_content