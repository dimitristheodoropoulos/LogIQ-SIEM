import pytest
import logging
from log_collector_linux import get_auth_token
from unittest.mock import patch, MagicMock

@pytest.fixture
def mock_cfg():
    return {"API_BASE_URL": "http://localhost:5000"}

def test_get_auth_token_success(mock_cfg, caplog):
    # Θέτουμε το επίπεδο του log για να είμαστε σίγουροι ότι το caplog καταγράφει τα πάντα
    caplog.set_level(logging.INFO)
    
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"access_token": "token"}
    mock_resp.status_code = 200
    
    with patch('requests.post', return_value=mock_resp):
        token = get_auth_token(mock_cfg['API_BASE_URL'], "u", "p")
        assert token == "token"
        
        # Ελέγχουμε αν υπάρχει το μήνυμα "Success" στα logs
        assert any("Success" in record.message for record in caplog.records)