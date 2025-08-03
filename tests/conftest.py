import pytest
import os
import tempfile
import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch # Import MagicMock and patch
from logiq.main import create_app, CustomFlask # Import CustomFlask for type hinting
from logiq.db.db_sqlite import SQLiteDatabase
from logiq.db.db_mongo import MongoDB # Import MongoDB for patching
from flask_jwt_extended import JWTManager # Import JWTManager here
from logiq.detectors.anomalies import AnomalyDetector
from logiq.detectors.brute_force import BruteForceDetector
from logiq.reports.report_generator import ReportGenerator
from typing import Union # Explicitly import Union for Python 3.8 compatibility
import shutil # Import shutil for robust directory cleanup

# Define a temporary in-memory database path for testing
TEST_DB_PATH = ':memory:'

@pytest.fixture(scope='function')
def mock_sqlite_db_instance():
    """Fixture to create a mock SQLiteDatabase instance for tests."""
    mock_db = MagicMock(spec=SQLiteDatabase)
    # Mock common methods that routes might call
    mock_db.insert_user.return_value = 1 # Default return for successful user insertion
    mock_db.find_by_username.return_value = None # Default: user not found
    mock_db.add_event.return_value = 1 # Default return for successful event addition
    mock_db.get_events.return_value = [] # Default: no events
    mock_db.get_all_events.return_value = [] # Default: no events
    mock_db.get_alerts.return_value = [] # Default: no alerts
    mock_db.connect = MagicMock()
    mock_db.create_tables = MagicMock()
    mock_db.close = MagicMock()
    mock_db.conn = MagicMock() # Ensure conn is a mock by default for execute calls
    mock_db.conn.cursor.return_value.execute.return_value = None
    mock_db.conn.commit.return_value = None
    return mock_db

@pytest.fixture(scope='function')
def mock_mongo_db_instance():
    """Fixture to create a mock MongoDB instance for tests."""
    mock_mongo = MagicMock(spec=MongoDB)
    
    # Mock the internal pymongo client, db, and collection objects
    mock_client_internal = MagicMock()
    mock_db_internal = MagicMock()
    mock_collection_internal = MagicMock() # Default for security_events
    mock_users_collection_internal = MagicMock()
    mock_alerts_collection_internal = MagicMock()

    # Configure mock_client_internal to return the mock db when accessed like client[db_name]
    mock_client_internal.__getitem__.return_value = mock_db_internal
    mock_client_internal.admin = MagicMock() # Mock the admin attribute
    mock_client_internal.admin.command.return_value = {'ismaster': True} # For connect()

    # Configure mock_db_internal to return specific mock collections when accessed like db['collection_name']
    mock_db_internal.__getitem__.side_effect = lambda key: {
        'users': mock_users_collection_internal,
        'security_events': mock_collection_internal,
        'alerts': mock_alerts_collection_internal
    }.get(key, MagicMock()) # Fallback for unexpected collection names

    # Configure methods on the internal collection mocks
    # Simulate initial state where indexes might not exist for create_tables to run
    mock_users_collection_internal.index_information.return_value = {}
    mock_collection_internal.index_information.return_value = {}

    mock_users_collection_internal.find_one.return_value = None # Default: user not found
    mock_users_collection_internal.insert_one.return_value.inserted_id = "mock_user_id_from_db"
    mock_users_collection_internal.create_index = MagicMock() # Ensure create_index is a callable mock

    mock_collection_internal.insert_one.return_value.inserted_id = "mock_event_id_from_db"
    mock_collection_internal.find_one.return_value = None # Default: event not found
    # Mock find to return an iterable object that can be converted to a list
    mock_find_cursor = MagicMock()
    mock_find_cursor.__iter__.return_value = iter([]) # Default to empty iterable
    mock_collection_internal.find.return_value = mock_find_cursor
    mock_collection_internal.create_index = MagicMock() # Ensure create_index is a callable mock

    mock_alerts_collection_internal.find.return_value = MagicMock(spec=list) # Mock cursor as iterable list
    mock_alerts_collection_internal.find.return_value.__iter__.return_value = []


    # Assign these internal mocks to the mock_mongo instance's attributes
    mock_mongo.client = mock_client_internal
    mock_mongo.db = mock_db_internal
    mock_mongo.collection = mock_collection_internal # This is self.collection in db_mongo.py

    # Mock MongoDB's own methods (the ones directly called on the MongoDB instance)
    mock_mongo.connect = MagicMock(side_effect=lambda: (
        setattr(mock_mongo, 'db', mock_db_internal),
        setattr(mock_mongo, 'collection', mock_collection_internal),
        None # Explicitly return None as connect doesn't return anything
    ))
    mock_mongo.close = MagicMock()
    mock_mongo.create_tables = MagicMock(side_effect=lambda: (
        mock_users_collection_internal.create_index("username", unique=True),
        mock_collection_internal.create_index("timestamp"),
        mock_collection_internal.create_index("hostname"),
        mock_collection_internal.create_index("event_type"),
        mock_collection_internal.create_index("ip")
    ))

    # Set up return values for the MongoDB class's methods that are called by routes/CLI
    mock_mongo.insert_user.side_effect = lambda u, p: (
        None if mock_users_collection_internal.find_one({"username": u}) else mock_users_collection_internal.insert_one({"username": u, "password": p}).inserted_id
    )
    mock_mongo.find_by_username.side_effect = lambda u: mock_users_collection_internal.find_one({"username": u})
    mock_mongo.add_event.side_effect = lambda e_data: (
        None if "invalid-date" in e_data.get("timestamp", "") else mock_collection_internal.insert_one(e_data).inserted_id
    )
    mock_mongo.get_events.side_effect = lambda **kwargs: list(mock_collection_internal.find(kwargs))
    mock_mongo.get_all_events.side_effect = lambda: list(mock_collection_internal.find({}))
    mock_mongo.get_alerts.side_effect = lambda **kwargs: list(mock_alerts_collection_internal.find(kwargs))

    return mock_mongo

@pytest.fixture(scope='function')
def mock_report_generator():
    """Fixture to provide a mock ReportGenerator instance."""
    mock_generator = MagicMock(spec=ReportGenerator)
    mock_generator.generate_summary.return_value = {"total_events": 0, "summary_data": "mock summary"}
    return mock_generator

@pytest.fixture(scope="function")
def app(mock_sqlite_db_instance, mock_mongo_db_instance, mock_report_generator):
    """
    Fixture to create and configure a Flask app for testing.
    Uses mocked database instances.
    Ensures the app, db, and JWTManager are fully initialized for each test.
    """
    # Create a temporary directory for UPLOAD_FOLDER for each test function
    temp_upload_dir = tempfile.mkdtemp()

    config = {
        'TESTING': True,
        'DATABASE_TYPE': 'sqlite', # Default to sqlite for most tests, can be overridden by specific test fixtures
        'DATABASE_URI': TEST_DB_PATH,
        'JWT_SECRET_KEY': 'super-secret-test-key',
        'TOKEN_EXPIRY_MINUTES': 5,
        'UPLOAD_FOLDER': temp_upload_dir, # Use the temporary directory
        'LOG_FILE_PATH': 'test_auth.log',
        "ANOMALIES_THRESHOLD_FACTOR": 2,
        "ANOMALIES_TIME_WINDOW": 3600,
        "ANOMALIES_MIN_EVENTS_FOR_BASELINE": 5,
        "BRUTE_FORCE_THRESHOLD": 5,
        "BRUTE_FORCE_TIME_WINDOW": 300,
        "API_BASE_URL": "http://localhost:5000/api",
        "AUTH_USERNAME": "testuser",
        "AUTH_PASSWORD": "testpassword"
    }

    # Patch load_config to ensure it always returns a valid config dict
    with patch('logiq.main.load_config', return_value=config):
        # Patch the database classes themselves within main.py's scope
        with patch('logiq.main.SQLiteDatabase', return_value=mock_sqlite_db_instance), \
             patch('logiq.main.MongoDB', return_value=mock_mongo_db_instance):

            app_instance = create_app(config=config, db_type=config['DATABASE_TYPE'])

            if app_instance is None:
                raise RuntimeError("Failed to create Flask app in test fixture. create_app returned None.")

            test_app: CustomFlask = app_instance

            # Explicitly set app.db to the correct mock based on config['DATABASE_TYPE']
            if config['DATABASE_TYPE'] == 'sqlite':
                test_app.db = mock_sqlite_db_instance
            elif config['DATABASE_TYPE'] == 'mongo':
                test_app.db = mock_mongo_db_instance
            else:
                test_app.db = mock_sqlite_db_instance # Fallback to SQLite mock

            # Ensure detectors are attached and mocked
            # Initialize with MagicMock instances directly
            test_app.detectors = [MagicMock(spec=AnomalyDetector), MagicMock(spec=BruteForceDetector)]
            for detector in test_app.detectors:
                # Ensure the 'detect' method itself is a mock that can have return_value set
                detector.detect = MagicMock(return_value=[]) # Mock the method specifically

            # Ensure report_generator is attached
            test_app.report_generator = mock_report_generator

            with test_app.app_context():
                # Removed real DB clearing operations, as this is a mock DB.
                # Mocks are reset per function scope by pytest.
                yield test_app

            # Teardown: close the database connection and clean up
            with test_app.app_context():
                if hasattr(test_app, 'db') and test_app.db:
                    test_app.db.close()
                # Clean up the temporary upload folder
                if os.path.exists(temp_upload_dir):
                    shutil.rmtree(temp_upload_dir, ignore_errors=True)
        
@pytest.fixture(scope="function")
def client(app):
    """
    A test client for the app.
    This client is used to make requests to the Flask application.
    It depends on the 'app' fixture.
    """
    with app.test_client() as client:
        yield client

@pytest.fixture(scope="function")
def sqlite_db_with_data(app, mock_sqlite_db_instance): # Add mock_sqlite_db_instance as a dependency
    """
    Fixture that provides a fresh SQLite database instance with some sample data.
    Ensures data is cleared before each function test and re-populated.
    Depends on the 'app' fixture to get the database.
    This fixture should only be used for tests specifically targeting SQLite behavior.
    """
    with app.app_context():
        # Ensure we are working with the SQLite mock if the app fixture is set to SQLite
        if app.config['DATABASE_TYPE'] == 'sqlite':
            db = mock_sqlite_db_instance # Use the mock here
            # Reset mock calls for this specific test's setup
            db.reset_mock()
            db.insert_user.return_value = 1
            db.add_event.return_value = 1
            db.find_by_username.return_value = None # Reset default

            # Simulate adding data to the mock
            db.insert_user('testuser', 'hashed_test_password') # Use a hashed password here
            db.find_by_username.return_value = {'username': 'testuser', 'password': 'hashed_test_password'}

            sample_events = [
                {"timestamp": datetime.now().isoformat(), "hostname": "host1", "event_type": "login_success", "process": "sshd", "message": "User testuser logged in", "ip": "10.0.0.1"},
                {"timestamp": (datetime.now() - timedelta(hours=1)).isoformat(), "hostname": "host2", "event_type": "failed_login", "process": "sshd", "message": "User root failed to login", "ip": "10.0.0.2"}
            ]
            for event in sample_events:
                db.add_event(event)

            yield db
        else:
            pytest.skip("sqlite_db_with_data fixture skipped: DATABASE_TYPE is not 'sqlite'")

