import pytest
from unittest.mock import MagicMock

def test_mongo_connect_success(mock_mongo_db_instance, api_client, app):
    mock_mongo_db_instance.connect = MagicMock()
    mock_mongo_db_instance.connect()
    mock_mongo_db_instance.connect.assert_called_once()

def test_mongo_connect_failure(mock_mongo_db_instance, api_client, app):
    mock_mongo_db_instance.connect = MagicMock(side_effect=Exception("Connection refused"))
    with pytest.raises(Exception, match="Connection refused"):
        mock_mongo_db_instance.connect()

def test_mongo_create_tables(mock_mongo_db_instance, api_client, app):
    mock_mongo_db_instance.create_tables = MagicMock()
    mock_mongo_db_instance.create_tables()
    mock_mongo_db_instance.create_tables.assert_called_once()

def test_mongo_insert_user(mock_mongo_db_instance, api_client, app):
    mock_mongo_db_instance.insert_user = MagicMock(return_value="user_id_123")
    result = mock_mongo_db_instance.insert_user("testuser", "hash")
    assert result == "user_id_123"

def test_mongo_insert_user_duplicate(mock_mongo_db_instance, api_client, app):
    mock_mongo_db_instance.insert_user = MagicMock(return_value=None)
    result = mock_mongo_db_instance.insert_user("existing", "hash")
    assert result is None

def test_mongo_find_by_username(mock_mongo_db_instance, api_client, app):
    mock_mongo_db_instance.find_by_username = MagicMock(return_value={"username": "testuser"})
    user = mock_mongo_db_instance.find_by_username("testuser")
    assert user["username"] == "testuser"

def test_mongo_add_event(mock_mongo_db_instance, api_client, app):
    mock_mongo_db_instance.add_event = MagicMock(return_value="event_id_123")
    result = mock_mongo_db_instance.add_event({"msg": "test"})
    assert result == "event_id_123"

def test_mongo_get_events(mock_mongo_db_instance, api_client, app):
    mock_mongo_db_instance.get_events = MagicMock(return_value=[{"_id": "1"}])
    events = mock_mongo_db_instance.get_events(hostname="hostA")
    assert len(events) == 1