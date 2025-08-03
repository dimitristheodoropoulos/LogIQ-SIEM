from __future__ import annotations # Added for deferred evaluation of type hints

import sqlite3
import os
import logging
from datetime import datetime
import json
from typing import Union # Imported Union

# Define the path to the database file
DB_PATH = 'logiq.db'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SQLiteDatabase:
    """
    Manages SQLite database connections and operations.
    This class consolidates all database-related functionalities.
    """
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.conn: Union[sqlite3.Connection, None] = None # Explicitly type hint conn
        self.cursor: Union[sqlite3.Cursor, None] = None # Explicitly type hint cursor
        logger.info(f"SQLiteDatabase initialized with path: {self.db_path}")

    def connect(self):
        """
        Establishes a connection to the SQLite database.
        
        :raises ConnectionError: If there's an error connecting to the database.
        """
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row # Allows accessing columns by name
            self.cursor = self.conn.cursor()
            logger.info(f"Connected to SQLite database: {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Error connecting to database: {e}")
            raise ConnectionError(f"Failed to connect to database: {e}") from e

    def close(self):
        """Closes the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None # Ensure connection is set to None after closing
            self.cursor = None # Ensure cursor is also set to None
            logger.info(f"Closed connection to SQLite database: {self.db_path}")

    def create_tables(self):
        """
        Creates all necessary tables (users, security_events, alerts) in the database
        if they don't already exist.
        """
        if not self.conn:
            raise RuntimeError("Database not connected. Call connect() first.")
        
        # Fix: Assert cursor is not None to satisfy Pylance
        assert self.cursor is not None 

        try:
            # Create users table
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL
                )
            """)
            
            # Create security_events table
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    hostname TEXT,
                    event_type TEXT NOT NULL,
                    process TEXT,
                    message TEXT NOT NULL,
                    ip TEXT,
                    details TEXT
                )
            """)
            
            # Create alerts table
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT
                )
            """)
            
            self.conn.commit()
            logger.info("Database tables checked/created successfully.")
        except sqlite3.Error as e:
            logger.error(f"Error creating tables: {e}")
            raise RuntimeError(f"Failed to create database tables: {e}") from e

    def insert_user(self, username: str, hashed_password: str) -> Union[int, None]:
        """
        Inserts a new user into the 'users' table.
        Returns the ID of the new user or None if the user already exists.
        """
        if not self.conn:
            raise RuntimeError("Database not connected.")
        
        # Fix: Assert cursor is not None to satisfy Pylance
        assert self.cursor is not None 

        try:
            self.cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            self.conn.commit()
            return self.cursor.lastrowid
        except sqlite3.IntegrityError:
            logger.warning(f"User '{username}' already exists.")
            return None
        except sqlite3.Error as e:
            logger.error(f"Error inserting user '{username}': {e}")
            raise

    def find_by_username(self, username: str) -> Union[sqlite3.Row, None]:
        """
        Retrieves a user by their username from the 'users' table.
        Returns a sqlite3.Row object or None if not found.
        """
        if not self.conn:
            raise RuntimeError("Database not connected.")
        
        # Fix: Assert cursor is not None to satisfy Pylance
        assert self.cursor is not None 

        self.cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return self.cursor.fetchone()

    def add_event(self, event_data: dict) -> Union[int, None]:
        """
        Inserts a single security event into the 'security_events' table.
        Returns the ID of the new event.
        """
        if not self.conn:
            raise RuntimeError("Database not connected.")
        
        # Fix: Assert cursor is not None to satisfy Pylance
        assert self.cursor is not None 

        try:
            timestamp = event_data.get('timestamp', datetime.now().isoformat())
            hostname = event_data.get('hostname')
            event_type = event_data.get('event_type')
            process = event_data.get('process')
            message = event_data.get('message')
            ip = event_data.get('ip')
            details = json.dumps(event_data.get('details')) if event_data.get('details') is not None else None

            self.cursor.execute(
                """
                INSERT INTO security_events (timestamp, hostname, event_type, process, message, ip, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp, hostname, event_type, process, message, ip, details)
            )
            self.conn.commit()
            return self.cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error adding event: {e}")
            self.conn.rollback()
            raise

    def get_events(self, start_date: Union[datetime, None] = None, end_date: Union[datetime, None] = None) -> list[sqlite3.Row]:
        """
        Retrieves security events from the 'security_events' table within a date range.
        """
        if not self.conn:
            raise RuntimeError("Database not connected.")
        
        # Fix: Assert cursor is not None to satisfy Pylance
        assert self.cursor is not None 

        query = "SELECT * FROM security_events"
        params = []
        conditions = []

        if start_date:
            conditions.append("timestamp >= ?")
            params.append(start_date.isoformat())
        if end_date:
            conditions.append("timestamp <= ?")
            params.append(end_date.isoformat())
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        self.cursor.execute(query, params)
        return self.cursor.fetchall()

    def get_alerts(self, time_window_minutes: int) -> list[dict]:
        """
        Retrieves security alerts within a specified time window.
        This is a placeholder and should be implemented based on how alerts are stored.
        """
        logger.warning("get_alerts method in SQLiteDatabase is a placeholder. Implement actual alert retrieval logic.")
        # Example: return some mock alerts or an empty list
        return []

    def get_all_events(self) -> list[sqlite3.Row]:
        """Retrieves all security events from the 'security_events' table."""
        if not self.conn:
            raise RuntimeError("Database not connected.")
        
        # Fix: Assert cursor is not None to satisfy Pylance
        assert self.cursor is not None 

        self.cursor.execute("SELECT * FROM security_events")
        return self.cursor.fetchall()
