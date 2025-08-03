from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
import json
import os

# Attempt to import ObjectId for testing its conversion
try:
    from bson.objectid import ObjectId
    from pymongo.errors import DuplicateKeyError
except ImportError:
    ObjectId = None # Fallback if bson is not installed in test env
    DuplicateKeyError = type('DuplicateKeyError', (Exception,), {}) # Define a mock DuplicateKeyError

# Import fixtures from conftest.py
from logiq.tests.conftest import mock_mongo_db_instance, app, client # Import necessary fixtures

# The 'app' fixture from conftest.py will set up the mock_mongo_db_instance correctly.
# We don't need to redefine mock_mongo_db_instance or app here.

def test_mongo_connect_success(mock_mongo_db_instance):
    """Test successful MongoDB connection."""
    # The fixture already returns a connected mock, so just assert its state
    mock_mongo_db_instance.connect.assert_called_once()
    assert mock_mongo_db_instance.client is not None
    assert mock_mongo_db_instance.db is not None
    assert mock_mongo_db_instance.collection is not None

def test_mongo_connect_failure(mock_mongo_db_instance):
    """Test MongoDB connection failure."""
    # Reset mock for this specific test to control its side_effect
    mock_mongo_db_instance.connect.reset_mock(side_effect=True)
    mock_mongo_db_instance.connect.side_effect = Exception("Connection refused")
    with pytest.raises(Exception, match="Connection refused"):
        mock_mongo_db_instance.connect()
    mock_mongo_db_instance.connect.assert_called_once()

def test_mongo_create_tables(mock_mongo_db_instance):
    """Test create_tables method (should create indexes)."""
    # Access the internal mocks that db_mongo.py will interact with
    mock_users_collection = mock_mongo_db_instance.db['users']
    mock_security_events_collection = mock_mongo_db_instance.db['security_events']

    # Ensure index_information returns an empty dict to simulate no existing indexes
    mock_users_collection.index_information.return_value = {}
    mock_security_events_collection.index_information.return_value = {}

    mock_mongo_db_instance.create_tables()
    mock_mongo_db_instance.create_tables.assert_called_once()
    
    # Assert that create_index was called on the correct internal mocks
    mock_users_collection.create_index.assert_called_once_with("username", unique=True)
    # Use assert_any_call for multiple calls with different arguments
    mock_security_events_collection.create_index.assert_any_call("timestamp")
    mock_security_events_collection.create_index.assert_any_call("hostname")
    mock_security_events_collection.create_index.assert_any_call("event_type")
    mock_security_events_collection.create_index.assert_any_call("ip")


def test_mongo_insert_user(mock_mongo_db_instance):
    """Test inserting a new user."""
    username = "testuser"
    hashed_password = "hashedpassword"
    
    # Access the internal mock for the 'users' collection
    mock_users_collection = mock_mongo_db_instance.db['users']
    
    # Simulate user not existing and successful insertion
    mock_users_collection.find_one.return_value = None
    mock_users_collection.insert_one.return_value.inserted_id = "user_id_123"

    result = mock_mongo_db_instance.insert_user(username, hashed_password)
    assert result == "user_id_123" 
    mock_users_collection.find_one.assert_called_once_with({"username": username})
    mock_users_collection.insert_one.assert_called_once_with({"username": username, "password": hashed_password})

def test_mongo_insert_user_duplicate(mock_mongo_db_instance):
    """Test inserting a duplicate user."""
    username = "existinguser"
    hashed_password = "hashedpassword"
    
    mock_users_collection = mock_mongo_db_instance.db['users']
    
    # Simulate user existing
    mock_users_collection.find_one.return_value = {"username": username}
    # Ensure insert_one is *not* called if find_one returns a user
    mock_users_collection.insert_one.reset_mock() # Ensure no prior calls are counted

    result = mock_mongo_db_instance.insert_user(username, hashed_password)
    assert result is None # Should return None for duplicate
    mock_users_collection.find_one.assert_called_once_with({"username": username})
    mock_users_collection.insert_one.assert_not_called()


def test_mongo_find_by_username(mock_mongo_db_instance):
    """Test finding a user by username."""
    username = "testuser"
    
    mock_users_collection = mock_mongo_db_instance.db['users']
    
    # Simulate user found, with a MagicMock that behaves like ObjectId
    user_id_str = "60c72b2f9b1d8e001f8e4d6a"
    # The mock's find_one should return a dict with a string _id, as db_mongo.py converts it
    mock_users_collection.find_one.return_value = {"_id": user_id_str, "username": username, "password": "hashedpassword"}

    user = mock_mongo_db_instance.find_by_username(username)
    
    assert user == {"_id": user_id_str, "username": username, "password": "hashedpassword"}
    mock_users_collection.find_one.assert_called_once_with({"username": username})

def test_mongo_find_by_username_not_found(mock_mongo_db_instance):
    """Test finding a user that does not exist."""
    username = "nonexistent"
    
    mock_users_collection = mock_mongo_db_instance.db['users']
    mock_users_collection.find_one.return_value = None

    user = mock_mongo_db_instance.find_by_username(username)
    assert user is None
    mock_users_collection.find_one.assert_called_once_with({"username": username})


def test_mongo_add_event(mock_mongo_db_instance):
    """Test adding a security event."""
    event_data = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "hostname": "host1",
        "event_type": "test_event",
        "message": "Test message",
        "details": {"key": "value"}
    }
    
    mock_security_events_collection = mock_mongo_db_instance.db['security_events']
    mock_security_events_collection.insert_one.return_value.inserted_id = "event_id_123"

    result = mock_mongo_db_instance.add_event(event_data)
    assert result == "event_id_123"
    
    mock_security_events_collection.insert_one.assert_called_once()
    args, kwargs = mock_security_events_collection.insert_one.call_args
    inserted_event = args[0]
    assert isinstance(inserted_event['timestamp'], datetime)
    assert inserted_event['details'] == json.dumps({"key": "value"})
    assert inserted_event['hostname'] == "host1"

def test_mongo_add_event_invalid_timestamp(mock_mongo_db_instance):
    """Test adding an event with an invalid timestamp format."""
    event_data = {
        "timestamp": "invalid-date",
        "hostname": "host1",
        "event_type": "test_event",
        "message": "Test message"
    }
    mock_security_events_collection = mock_mongo_db_instance.db['security_events']
    
    result = mock_mongo_db_instance.add_event(event_data)
    assert result is None
    mock_security_events_collection.insert_one.assert_not_called()

def test_mongo_get_events(mock_mongo_db_instance):
    """Test retrieving events with filters."""
    start_date = datetime.utcnow() - timedelta(days=1)
    end_date = datetime.utcnow()
    
    mock_events_from_db = [
        {"_id": "60c72b2f9b1d8e001f8e4d6b", "timestamp": start_date, "hostname": "hostA", "event_type": "typeX", "message": "msg1", "details": json.dumps({"d1":1}), "ip": "1.1.1.1", "process": "proc1"},
        {"_id": "60c72b2f9b1d8e001f8e4d6c", "timestamp": end_date, "hostname": "hostB", "event_type": "typeY", "message": "msg2", "details": None, "ip": "2.2.2.2", "process": None},
    ]
    
    mock_security_events_collection = mock_mongo_db_instance.db['security_events']
    mock_find_cursor = MagicMock()
    mock_find_cursor.__iter__.return_value = iter(mock_events_from_db)
    mock_security_events_collection.find.return_value = mock_find_cursor

    events = mock_mongo_db_instance.get_events(start_date=start_date, end_date=end_date, hostname="hostA")
    
    assert len(events) == 2
    assert events[0]['_id'] == "60c72b2f9b1d8e001f8e4d6b"
    assert events[0]['details'] == {"d1":1}
    assert events[1]['details'] is None
    
    mock_security_events_collection.find.assert_called_once()
    args, kwargs = mock_security_events_collection.find.call_args
    assert "timestamp" in args[0]
    assert args[0]["hostname"] == "hostA"


def test_mongo_get_all_events(mock_mongo_db_instance):
    """Test retrieving all events."""
    mock_all_events_from_db = [
        {"_id": "60c72b2f9b1d8e001f8e4d6d", "timestamp": datetime.utcnow(), "hostname": "hostC", "event_type": "typeZ", "message": "msg3", "details": None, "ip": "3.3.3.3", "process": "proc3"},
        {"_id": "60c72b2f9b1d8e001f8e4d6e", "timestamp": datetime.utcnow(), "hostname": "hostD", "event_type": "typeW", "message": "msg4", "details": json.dumps({"d2":2}), "ip": None, "process": None},
    ]
    
    mock_security_events_collection = mock_mongo_db_instance.db['security_events']
    mock_find_cursor = MagicMock()
    mock_find_cursor.__iter__.return_value = iter(mock_all_events_from_db)
    mock_security_events_collection.find.return_value = mock_find_cursor

    events = mock_mongo_db_instance.get_all_events()
    assert len(events) == 2
    assert events[0]['_id'] == "60c72b2f9b1d8e001f8e4d6d"
    assert events[1]['details'] == {"d2":2}
    
    mock_security_events_collection.find.assert_called_once_with({})

def test_mongo_get_alerts(mock_mongo_db_instance):
    """Test retrieving alerts."""
    mock_alerts_collection = mock_mongo_db_instance.db['alerts']
    
    mock_alerts_from_db = [
        {"_id": "60c72b2f9b1d8e001f8e4d6f", "alert_type": "brute_force", "timestamp": datetime.utcnow()},
        {"_id": "60c72b2f9b1d8e001f8e4d70", "alert_type": "anomaly", "timestamp": datetime.utcnow()},
    ]
    mock_find_cursor = MagicMock()
    mock_find_cursor.__iter__.return_value = iter(mock_alerts_from_db)
    mock_alerts_collection.find.return_value = mock_find_cursor

    alerts = mock_mongo_db_instance.get_alerts(alert_type="brute_force")
    
    assert len(alerts) == 2
    assert alerts[0]['_id'] == "60c72b2f9b1d8e001f8e4d6f"
    
    mock_alerts_collection.find.assert_called_once()
    args, kwargs = mock_alerts_collection.find.call_args
    assert args[0]["alert_type"] == "brute_force"