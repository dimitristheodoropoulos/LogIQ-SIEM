import pytest
from unittest.mock import MagicMock
from main import create_app

@pytest.fixture(scope="function")
def mock_db():
    """Δημιουργεί ένα καθολικό Mock για τη βάση δεδομένων."""
    db = MagicMock()
    db.insert_user.return_value = 1
    db.find_by_username.return_value = None
    db.add_event.return_value = 1
    db.get_all_events.return_value = []
    db.get_alerts.return_value = []
    return db

@pytest.fixture(scope="function")
def mock_report_gen():
    """Δημιουργεί ένα καθολικό Mock για το report generator."""
    rg = MagicMock()
    rg.generate_summary.return_value = {"total_events": 0, "time_window": "24h"}
    return rg

@pytest.fixture(scope="function")
def app(mock_db, mock_report_gen):
    """Δημιουργεί την εφαρμογή Flask εισάγοντας τα απαραίτητα mocks."""
    # Διόρθωση: Αυξημένο μήκος JWT_SECRET_KEY για αποφυγή InsecureKeyLengthWarning
    config = {
        'TESTING': True, 
        'DATABASE_URI': ':memory:', 
        'JWT_SECRET_KEY': 'super-secure-key-must-be-at-least-32-chars-long-1234567890',
        'UPLOAD_FOLDER': '/tmp'
    }
    app_instance = create_app(config=config)
    # Σύνδεση των mocks στο app instance
    app_instance.db = mock_db
    app_instance.report_generator = mock_report_gen
    yield app_instance

@pytest.fixture(scope="function")
def client(app):
    """Δημιουργεί τον test client για την εφαρμογή."""
    return app.test_client()

@pytest.fixture(scope="function")
def api_client(client):
    """Alias fixture για υποστήριξη του ονόματος 'api_client'."""
    return client

@pytest.fixture(scope="function")
def sample_events():
    """Fixture που επιστρέφει δείγμα events για δοκιμές αναφορών."""
    return [
        {"timestamp": "2023-01-01T12:00:00Z", "event_type": "login_success", "message": "msg1"},
        {"timestamp": "2023-01-01T13:00:00Z", "event_type": "ssh_failed_password", "message": "msg2"},
        {"timestamp": "2023-01-01T14:00:00Z", "event_type": "login_success", "message": "msg3"},
        {"timestamp": "2023-01-02T12:00:00Z", "event_type": "sudo_command", "message": "msg4"},
        {"timestamp": "2023-01-03T12:00:00Z", "event_type": "info", "message": "msg5"}
    ]

@pytest.fixture(scope="function")
def mock_mongo_db_instance():
    """Fixture για την προσομοίωση της MongoDatabase."""
    db_mock = MagicMock()
    db_mock.client = MagicMock()
    db_mock.db = {
        'users': MagicMock(),
        'security_events': MagicMock()
    }
    return db_mock