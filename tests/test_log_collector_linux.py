import pytest
from unittest.mock import patch, MagicMock
# FIX: Import from logiq.log_collector_linux
from logiq.log_collector_linux import get_auth_token, send_events, read_auth_log 
# FIX: Import parse_auth_log from its absolute path for mocking
from logiq.parsers.auth_parser import parse_auth_log 
from io import StringIO
import sys
import requests # Import requests for mocking exceptions
import logging # Import logging to capture log messages

@pytest.fixture
def mock_config():
    return {
        "API_BASE_URL": "http://localhost:5000", # Base URL without /api
        "AUTH_USERNAME": "testuser",
        "AUTH_PASSWORD": "testpassword"
    }

@pytest.fixture
def caplog_setup(caplog):
    """Fixture to capture logging messages."""
    caplog.set_level(logging.INFO) # Capture INFO and above
    yield caplog

def test_get_auth_token_success(mock_config, caplog_setup):
    """Test successful JWT token retrieval."""
    mock_response = MagicMock()
    mock_response.json.return_value = {"access_token": "mock_jwt_token"}
    mock_response.status_code = 200 # Ensure status code is 200
    mock_response.raise_for_status.return_value = None # No HTTP errors
    
    with patch('requests.post', return_value=mock_response) as mock_post:
        token = get_auth_token(mock_config['API_BASE_URL'], mock_config['AUTH_USERNAME'], mock_config['AUTH_PASSWORD'])
        
        assert token == "mock_jwt_token"
        mock_post.assert_called_once_with(
            f"{mock_config['API_BASE_URL']}/api/login", 
            json={"username": mock_config['AUTH_USERNAME'], "password": mock_config['AUTH_PASSWORD']},
            timeout=10
        )
        assert "Επιτυχής λήψη JWT token" in caplog_setup.text # Check log message

def test_get_auth_token_auth_fail(mock_config, caplog_setup):
    """Test authentication failure during token retrieval."""
    mock_response = MagicMock()
    mock_response.json.return_value = {"error": "Invalid credentials"}
    mock_response.status_code = 401
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response)
    
    with patch('requests.post', return_value=mock_response) as mock_post:
        token = get_auth_token(mock_config['API_BASE_URL'], mock_config['AUTH_USERNAME'], mock_config['AUTH_PASSWORD'])
        
        assert token is None
        mock_post.assert_called_once()
        assert "Αποτυχία σύνδεσης" in caplog_setup.text # Check log message

def test_get_auth_token_api_error(mock_config, caplog_setup):
    """Test API error during token retrieval (e.g., network issue)."""
    with patch('requests.post', side_effect=requests.exceptions.RequestException("Network error")) as mock_post:
        token = get_auth_token(mock_config['API_BASE_URL'], mock_config['AUTH_USERNAME'], mock_config['AUTH_PASSWORD'])
        
        assert token is None
        mock_post.assert_called_once()
        assert "Σφάλμα κατά τη σύνδεση με το API: Network error" in caplog_setup.text # Check log message

def test_read_auth_log_file_not_found(caplog_setup):
    """Test reading a non-existent auth log file."""
    # FIX: Patch parse_auth_log directly as read_auth_log now calls it
    with patch('logiq.parsers.auth_parser.parse_auth_log', return_value=[]):
        # We don't need to mock os.path.exists here, parse_auth_log handles it
        events = read_auth_log("non_existent.log")
        assert events == []
        assert "Log file not found: non_existent.log" in caplog_setup.text # Check log message

def test_send_events_success(mock_config, caplog_setup):
    """Test successful sending of events to the API."""
    mock_response = MagicMock()
    mock_response.json.return_value = {"message": "Events received"}
    mock_response.status_code = 201 # Expected status code for success
    mock_response.raise_for_status.return_value = None
    
    events_to_send = [{"event": "test"}]
    with patch('requests.post', return_value=mock_response) as mock_post:
        success = send_events(f"{mock_config['API_BASE_URL']}/api/events", events_to_send, "mock_token")
        
        assert success is True
        mock_post.assert_called_once()
        assert "Επιτυχής αποστολή 1 συμβάντων στο API" in caplog_setup.text # Check log message

def test_send_events_api_error(mock_config, caplog_setup):
    """Test API error during sending events."""
    events_to_send = [{"event": "test"}]
    with patch('requests.post', side_effect=requests.exceptions.RequestException("API error")) as mock_post:
        success = send_events(f"{mock_config['API_BASE_URL']}/api/events", events_to_send, "mock_token")
        
        assert success is False
        mock_post.assert_called_once()
        assert "Εξαίρεση κατά την αποστολή συμβάντων στο API: API error" in caplog_setup.text # Check log message

def test_send_events_no_events(mock_config, caplog_setup):
    """Test sending events when the event list is empty."""
    with patch('requests.post') as mock_post:
        success = send_events(f"{mock_config['API_BASE_URL']}/api/events", [], "mock_token")
        
        assert success is False # FIX: Expect False now
        mock_post.assert_not_called()
        assert "Δεν υπάρχουν συμβάντα για αποστολή" in caplog_setup.text # Check log message
