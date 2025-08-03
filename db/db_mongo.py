from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
import json # Import json for serializing/deserializing details field

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, DuplicateKeyError
    from bson.objectid import ObjectId
except ImportError:
    # Handle cases where pymongo might not be installed (e.g., if only SQLite is used)
    MongoClient = None
    ConnectionFailure = type('ConnectionFailure', (Exception,), {})
    ServerSelectionTimeoutError = type('ServerSelectionTimeoutError', (Exception,), {})
    DuplicateKeyError = type('DuplicateKeyError', (Exception,), {})
    ObjectId = None
    logging.warning("PyMongo not found. MongoDB features will be unavailable.")

logger = logging.getLogger(__name__)

class MongoDB:
    """
    MongoDB database handler for Logiq SIEM.
    Manages connections, user operations, and security event storage.
    """

    def __init__(self, uri: str, db_name: str):
        if MongoClient is None:
            raise RuntimeError("PyMongo is not installed. Cannot use MongoDB.")
        self.uri = uri
        self.db_name = db_name
        self.client: Union[MongoClient, None] = None
        self.db: Any = None # Union[Database, None]
        self.collection: Any = None # Union[Collection, None]

    def connect(self):
        """Establishes a connection to the MongoDB database."""
        if self.client is None:
            try:
                self.client = MongoClient(self.uri, serverSelectionTimeoutMS=5000)
                # The ismaster command is cheap and does not require auth.
                self.client.admin.command('ismaster')
                self.db = self.client[self.db_name]
                self.collection = self.db['security_events'] # Default collection for events
                logger.info("Successfully connected to MongoDB.")
            except ServerSelectionTimeoutError as err:
                logger.critical(f"MongoDB server selection timeout: {err}")
                self.client = None
                raise ConnectionFailure(f"Could not connect to MongoDB: {err}")
            except ConnectionFailure as err:
                logger.critical(f"MongoDB connection failed: {err}")
                self.client = None
                raise ConnectionFailure(f"Could not connect to MongoDB: {err}")
            except Exception as e:
                logger.critical(f"An unexpected error occurred during MongoDB connection: {e}")
                self.client = None
                raise

    def close(self):
        """Closes the MongoDB connection."""
        if self.client:
            self.client.close()
            self.client = None
            self.db = None
            self.collection = None
            logger.info("MongoDB connection closed.")

    def create_tables(self):
        """
        Ensures necessary collections and indexes exist.
        For MongoDB, this primarily means creating indexes.
        """
        if self.db:
            # Create index for username on users collection if it doesn't exist
            users_collection = self.db['users']
            # Check if index exists before creating to avoid errors on repeated calls
            # index_information() returns a dictionary of existing indexes
            if "username_1" not in users_collection.index_information():
                users_collection.create_index("username", unique=True)
                logger.info("Index created for 'username' in 'users' collection.")
            
            # Create indexes for security_events collection
            if self.collection: # Ensure collection is not None
                if "timestamp_1" not in self.collection.index_information():
                    self.collection.create_index("timestamp")
                    logger.info("Index created for 'timestamp' in 'security_events' collection.")
                if "hostname_1" not in self.collection.index_information():
                    self.collection.create_index("hostname")
                    logger.info("Index created for 'hostname' in 'security_events' collection.")
                if "event_type_1" not in self.collection.index_information():
                    self.collection.create_index("event_type")
                    logger.info("Index created for 'event_type' in 'security_events' collection.")
                if "ip_1" not in self.collection.index_information():
                    self.collection.create_index("ip")
                    logger.info("Index created for 'ip' in 'security_events' collection.")
        else:
            logger.warning("Cannot create tables/indexes: MongoDB not connected.")

    def insert_user(self, username: str, hashed_password: str) -> Union[str, None]:
        """Inserts a new user into the database."""
        if not self.db:
            logger.error("MongoDB not connected. Cannot insert user.")
            return None
        users_collection = self.db['users']
        try:
            # Check if user already exists
            if users_collection.find_one({"username": username}):
                logger.warning(f"Attempted to insert duplicate user: {username}")
                return None # User already exists
            
            user_data = {"username": username, "password": hashed_password}
            result = users_collection.insert_one(user_data)
            logger.info(f"User {username} inserted with ID: {result.inserted_id}")
            return str(result.inserted_id)
        except DuplicateKeyError:
            logger.warning(f"Duplicate key error when inserting user: {username}")
            return None
        except Exception as e:
            logger.error(f"Error inserting user {username}: {e}")
            return None

    def find_by_username(self, username: str) -> Union[Dict[str, Any], None]:
        """Finds a user by username."""
        if not self.db:
            logger.error("MongoDB not connected. Cannot find user.")
            return None
        users_collection = self.db['users']
        try:
            user = users_collection.find_one({"username": username})
            if user:
                # Convert ObjectId to string for consistency with SQLite IDs
                if ObjectId and isinstance(user.get('_id'), ObjectId):
                    user['_id'] = str(user['_id'])
            return user
        except Exception as e:
            logger.error(f"Error finding user {username}: {e}")
            return None

    def add_event(self, event_data: Dict[str, Any]) -> Union[str, None]:
        """Adds a security event to the database."""
        if not self.collection:
            logger.error("MongoDB events collection not available. Cannot add event.")
            return None
        try:
            # Create a mutable copy of event_data
            event_to_insert = event_data.copy()

            # Ensure timestamp is in datetime format for MongoDB
            if 'timestamp' in event_to_insert and isinstance(event_to_insert['timestamp'], str):
                try:
                    event_to_insert['timestamp'] = datetime.fromisoformat(event_to_insert['timestamp'].replace('Z', '+00:00'))
                except ValueError:
                    logger.error(f"Invalid timestamp format for event: {event_to_insert['timestamp']}")
                    return None
            
            # Serialize 'details' field if it's a dictionary
            if 'details' in event_to_insert and isinstance(event_to_insert['details'], dict):
                event_to_insert['details'] = json.dumps(event_to_insert['details'])
            
            result = self.collection.insert_one(event_to_insert)
            logger.info(f"Event added with ID: {result.inserted_id}")
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error adding event: {e}", exc_info=True)
            return None

    def get_events(self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None,
                   hostname: Optional[str] = None, event_type: Optional[str] = None,
                   ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves security events based on filters."""
        if not self.collection:
            logger.error("MongoDB events collection not available. Cannot get events.")
            return []
        
        query: Dict[str, Any] = {}
        if start_date and end_date:
            query["timestamp"] = {"$gte": start_date, "$lte": end_date}
        elif start_date:
            query["timestamp"] = {"$gte": start_date}
        elif end_date:
            query["timestamp"] = {"$lte": end_date}

        if hostname:
            query["hostname"] = hostname
        if event_type:
            query["event_type"] = event_type
        if ip:
            query["ip"] = ip

        try:
            # Use list comprehension to convert cursor to list of dictionaries
            events = []
            for event in self.collection.find(query):
                # Convert ObjectId to string and deserialize 'details'
                if ObjectId and isinstance(event.get('_id'), ObjectId):
                    event['_id'] = str(event['_id'])
                if 'details' in event and isinstance(event['details'], str):
                    try:
                        event['details'] = json.loads(event['details'])
                    except json.JSONDecodeError:
                        logger.warning(f"Could not decode details for event ID {event.get('_id')}: {event['details']}")
                events.append(event)
            logger.info(f"Retrieved {len(events)} events with filters: {query}")
            return events
        except Exception as e:
            logger.error(f"Error retrieving events with filters {query}: {e}", exc_info=True)
            return []

    def get_all_events(self) -> List[Dict[str, Any]]:
        """Retrieves all security events."""
        if not self.collection:
            logger.error("MongoDB events collection not available. Cannot get all events.")
            return []
        try:
            events = []
            for event in self.collection.find({}):
                # Convert ObjectId to string and deserialize 'details'
                if ObjectId and isinstance(event.get('_id'), ObjectId):
                    event['_id'] = str(event['_id'])
                if 'details' in event and isinstance(event['details'], str):
                    try:
                        event['details'] = json.loads(event['details'])
                    except json.JSONDecodeError:
                        logger.warning(f"Could not decode details for event ID {event.get('_id')}: {event['details']}")
                events.append(event)
            logger.info(f"Retrieved {len(events)} all events.")
            return events
        except Exception as e:
            logger.error(f"Error retrieving all events: {e}", exc_info=True)
            return []

    def get_alerts(self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None,
                   alert_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves alerts based on filters."""
        if not self.db:
            logger.error("MongoDB not connected. Cannot get alerts.")
            return []
        alerts_collection = self.db['alerts'] # Assuming a separate 'alerts' collection
        query: Dict[str, Any] = {}
        if start_date and end_date:
            query["timestamp"] = {"$gte": start_date, "$lte": end_date}
        elif start_date:
            query["timestamp"] = {"$gte": start_date}
        elif end_date:
            query["timestamp"] = {"$lte": end_date}
        if alert_type:
            query["alert_type"] = alert_type

        try:
            alerts = []
            for alert in alerts_collection.find(query):
                if ObjectId and isinstance(alert.get('_id'), ObjectId):
                    alert['_id'] = str(alert['_id'])
                alerts.append(alert)
            logger.info(f"Retrieved {len(alerts)} alerts with filters: {query}")
            return alerts
        except Exception as e:
            logger.error(f"Error retrieving alerts with filters {query}: {e}", exc_info=True)
            return []

