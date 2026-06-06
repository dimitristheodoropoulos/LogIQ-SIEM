from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
import json 

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, DuplicateKeyError
    from bson.objectid import ObjectId
except ImportError:
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
    """

    def __init__(self, uri: str, db_name: str):
        if MongoClient is None:
            raise RuntimeError("PyMongo is not installed. Cannot use MongoDB.")
        self.uri = uri
        self.db_name = db_name
        self.client: Optional[Any] = None
        self.db: Any = None 
        self.collection: Any = None 

    def connect(self):
        """Establishes a connection to the MongoDB database."""
        # ΔΙΟΡΘΩΣΗ: Ρητός έλεγχος με is None
        if self.client is None:
            try:
                self.client = MongoClient(self.uri, serverSelectionTimeoutMS=5000)
                self.client.admin.command('ismaster')
                self.db = self.client[self.db_name]
                self.collection = self.db['security_events']
                logger.info("Successfully connected to MongoDB.")
            except Exception as e:
                logger.critical(f"An unexpected error occurred during MongoDB connection: {e}")
                self.client = None
                raise

    def close(self):
        """Closes the MongoDB connection."""
        # ΔΙΟΡΘΩΣΗ: Ρητός έλεγχος με is not None
        if self.client is not None:
            self.client.close()
            self.client = None
            self.db = None
            self.collection = None
            logger.info("MongoDB connection closed.")

    def create_tables(self):
        """Ensures necessary collections and indexes exist."""
        # ΔΙΟΡΘΩΣΗ: Ρητός έλεγχος με is not None
        if self.db is not None:
            users_collection = self.db['users']
            if "username_1" not in users_collection.index_information():
                users_collection.create_index("username", unique=True)
                logger.info("Index created for 'username' in 'users' collection.")
            
            if self.collection is not None: 
                for idx in ["timestamp", "hostname", "event_type", "ip"]:
                    if f"{idx}_1" not in self.collection.index_information():
                        self.collection.create_index(idx)
                        logger.info(f"Index created for '{idx}' in 'security_events' collection.")
        else:
            logger.warning("Cannot create tables/indexes: MongoDB not connected.")

    def insert_user(self, username: str, hashed_password: str) -> Union[str, None]:
        if self.db is None:
            logger.error("MongoDB not connected. Cannot insert user.")
            return None
        users_collection = self.db['users']
        try:
            if users_collection.find_one({"username": username}) is not None:
                logger.warning(f"Attempted to insert duplicate user: {username}")
                return None
            
            user_data = {"username": username, "password": hashed_password}
            result = users_collection.insert_one(user_data)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error inserting user {username}: {e}")
            return None

    def find_by_username(self, username: str) -> Union[Dict[str, Any], None]:
        if self.db is None:
            return None
        users_collection = self.db['users']
        try:
            user = users_collection.find_one({"username": username})
            if user is not None:
                if ObjectId and isinstance(user.get('_id'), ObjectId):
                    user['_id'] = str(user['_id'])
            return user
        except Exception as e:
            logger.error(f"Error finding user {username}: {e}")
            return None

    def add_event(self, event_data: Dict[str, Any]) -> Union[str, None]:
        if self.collection is None:
            logger.error("MongoDB events collection not available.")
            return None
        try:
            event_to_insert = event_data.copy()
            if 'timestamp' in event_to_insert and isinstance(event_to_insert['timestamp'], str):
                try:
                    event_to_insert['timestamp'] = datetime.fromisoformat(event_to_insert['timestamp'].replace('Z', '+00:00'))
                except ValueError:
                    return None
            
            if 'details' in event_to_insert and isinstance(event_to_insert['details'], dict):
                event_to_insert['details'] = json.dumps(event_to_insert['details'])
            
            result = self.collection.insert_one(event_to_insert)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error adding event: {e}")
            return None

    def get_events(self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None,
                   hostname: Optional[str] = None, event_type: Optional[str] = None,
                   ip: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.collection is None:
            return []
        
        query: Dict[str, Any] = {}
        if start_date or end_date:
            query["timestamp"] = {}
            if start_date: query["timestamp"]["$gte"] = start_date
            if end_date: query["timestamp"]["$lte"] = end_date

        if hostname: query["hostname"] = hostname
        if event_type: query["event_type"] = event_type
        if ip: query["ip"] = ip

        try:
            events = []
            for event in self.collection.find(query):
                if ObjectId and isinstance(event.get('_id'), ObjectId):
                    event['_id'] = str(event['_id'])
                if 'details' in event and isinstance(event['details'], str):
                    try:
                        event['details'] = json.loads(event['details'])
                    except: pass
                events.append(event)
            return events
        except Exception as e:
            logger.error(f"Error retrieving events: {e}")
            return []

    def get_all_events(self) -> List[Dict[str, Any]]:
        if self.collection is None:
            return []
        try:
            events = []
            for event in self.collection.find({}):
                if ObjectId and isinstance(event.get('_id'), ObjectId):
                    event['_id'] = str(event['_id'])
                if 'details' in event and isinstance(event['details'], str):
                    try:
                        event['details'] = json.loads(event['details'])
                    except: pass
                events.append(event)
            return events
        except Exception as e:
            logger.error(f"Error retrieving all events: {e}")
            return []

    def get_alerts(self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None,
                   alert_type: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.db is None:
            return []
        alerts_collection = self.db['alerts']
        query: Dict[str, Any] = {}
        if start_date or end_date:
            query["timestamp"] = {}
            if start_date: query["timestamp"]["$gte"] = start_date
            if end_date: query["timestamp"]["$lte"] = end_date
        if alert_type: query["alert_type"] = alert_type

        try:
            alerts = []
            for alert in alerts_collection.find(query):
                if ObjectId and isinstance(alert.get('_id'), ObjectId):
                    alert['_id'] = str(alert['_id'])
                alerts.append(alert)
            return alerts
        except Exception as e:
            logger.error(f"Error retrieving alerts: {e}")
            return []