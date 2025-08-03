import pytest
import sqlite3
import os
from datetime import datetime, timedelta
from logiq.db.db_sqlite import SQLiteDatabase # Import the class

# Define a temporary in-memory database path for testing
TEST_DB_PATH = ':memory:'

@pytest.fixture(scope='function')
def db_instance():
    """
    Fixture to provide a connected and initialized SQLiteDatabase instance for each test.
    Uses an in-memory database for isolation and speed.
    """
    db = SQLiteDatabase(TEST_DB_PATH)
    try:
        db.connect()
        db.create_tables()
        yield db
    finally:
        db.close()

def test_connect_db_success(db_instance):
    """Test that the database connects successfully."""
    assert db_instance.conn is not None
    assert isinstance(db_instance.conn, sqlite3.Connection)

def test_create_tables_executes_correct_sql(db_instance):
    """
    Test that create_tables creates the expected tables.
    We check by querying the sqlite_master table.
    """
    cursor = db_instance.conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row['name'] for row in cursor.fetchall()]
    
    assert 'users' in tables
    assert 'security_events' in tables
    assert 'alerts' in tables

def test_insert_user_function(db_instance):
    """Test inserting a user into the database."""
    username = "testuser"
    password_hash = "hashed_password"
    user_id = db_instance.insert_user(username, password_hash)
    
    assert user_id is not None
    
    # Verify the user was inserted
    user = db_instance.find_by_username(username)
    assert user is not None
    assert user['username'] == username
    assert user['password'] == password_hash

def test_insert_duplicate_user(db_instance):
    """Test inserting a duplicate user returns None."""
    username = "duplicate_user"
    password_hash = "hashed_password"
    
    first_insert_id = db_instance.insert_user(username, password_hash)
    assert first_insert_id is not None
    
    second_insert_id = db_instance.insert_user(username, password_hash)
    assert second_insert_id is None # Should return None for duplicate

def test_find_by_username(db_instance):
    """Test finding a user by username."""
    username = "findme"
    password_hash = "hashed_password"
    db_instance.insert_user(username, password_hash)
    
    found_user = db_instance.find_by_username(username)
    assert found_user is not None
    assert found_user['username'] == username

    not_found_user = db_instance.find_by_username("nonexistent")
    assert not_found_user is None

def test_add_event_function(db_instance):
    """Test adding a single event into the database."""
    event_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "hostname": "testhost",
        "event_type": "login_attempt",
        "process": "sshd",
        "message": "User testuser failed login",
        "ip": "192.168.1.1",
        "details": {"reason": "bad password"}
    }
    event_id = db_instance.add_event(event_data)
    
    assert event_id is not None
    
    # Verify the event was inserted
    events = db_instance.get_events()
    assert len(events) == 1
    assert events[0]['event_type'] == "login_attempt"
    assert events[0]['hostname'] == "testhost"

def test_get_events_no_filter(db_instance):
    """Test retrieving all events without filters."""
    event1 = {"timestamp": datetime.utcnow().isoformat(), "hostname": "h1", "event_type": "e1", "message": "m1"}
    event2 = {"timestamp": (datetime.utcnow() - timedelta(hours=1)).isoformat(), "hostname": "h2", "event_type": "e2", "message": "m2"}
    db_instance.add_event(event1)
    db_instance.add_event(event2)
    
    events = db_instance.get_events()
    assert len(events) == 2

def test_get_events_with_date_filter(db_instance):
    """Test retrieving events with start and end date filters."""
    now = datetime.utcnow()
    event1 = {"timestamp": (now - timedelta(days=2)).isoformat(), "hostname": "h1", "event_type": "e1", "message": "m1"}
    event2 = {"timestamp": (now - timedelta(days=1)).isoformat(), "hostname": "h2", "event_type": "e2", "message": "m2"}
    event3 = {"timestamp": now.isoformat(), "hostname": "h3", "event_type": "e3", "message": "m3"}
    
    db_instance.add_event(event1)
    db_instance.add_event(event2)
    db_instance.add_event(event3)

    # Filter for events in the last 1.5 days
    filtered_events = db_instance.get_events(start_date=now - timedelta(days=1, hours=12), end_date=now)
    assert len(filtered_events) == 2 # event2 and event3

    # Filter for only the most recent event
    single_event = db_instance.get_events(start_date=now - timedelta(minutes=1), end_date=now)
    assert len(single_event) == 1
    assert single_event[0]['hostname'] == "h3"

def test_get_all_events(db_instance):
    """Test retrieving all events using get_all_events."""
    event1 = {"timestamp": datetime.utcnow().isoformat(), "hostname": "h1", "event_type": "e1", "message": "m1"}
    event2 = {"timestamp": (datetime.utcnow() - timedelta(hours=1)).isoformat(), "hostname": "h2", "event_type": "e2", "message": "m2"}
    db_instance.add_event(event1)
    db_instance.add_event(event2)
    
    events = db_instance.get_all_events()
    assert len(events) == 2

def test_get_alerts_placeholder(db_instance):
    """Test the placeholder get_alerts method."""
    alerts = db_instance.get_alerts(time_window_minutes=60)
    assert isinstance(alerts, list)
    assert len(alerts) == 0 # Expect empty list as it's a placeholder
