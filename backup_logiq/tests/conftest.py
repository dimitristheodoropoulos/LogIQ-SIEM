import pytest
import os
import tempfile
import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
import shutil
from typing import Union

from main import create_app, CustomFlask
from db.db_sqlite import SQLiteDatabase
from db.db_mongo import MongoDB
from detectors.anomalies import AnomalyDetector
from detectors.brute_force import BruteForceDetector
from reports.report_generator import ReportGenerator

TEST_DB_PATH = ':memory:'


@pytest.fixture(scope='function')
def mock_sqlite_db_instance():
    mock_db = MagicMock(spec=SQLiteDatabase)

    mock_db.insert_user.return_value = 1
    mock_db.find_by_username.return_value = None
    mock_db.add_event.return_value = 1
    mock_db.get_events.return_value = []
    mock_db.get_all_events.return_value = []
    mock_db.get_alerts.return_value = []

    mock_db.connect = MagicMock()
    mock_db.create_tables = MagicMock()
    mock_db.close = MagicMock()

    mock_db.conn = MagicMock()
    mock_db.conn.cursor.return_value.execute.return_value = None
    mock_db.conn.commit.return_value = None

    return mock_db


@pytest.fixture(scope='function')
def mock_mongo_db_instance():
    mock_mongo = MagicMock(spec=MongoDB)

    mock_client_internal = MagicMock()
    mock_db_internal = MagicMock()
    mock_collection_internal = MagicMock()
    mock_users_collection = MagicMock()
    mock_alerts_collection = MagicMock()

    mock_client_internal.__getitem__.return_value = mock_db_internal
    mock_client_internal.admin = MagicMock()
    mock_client_internal.admin.command.return_value = {'ismaster': True}

    mock_db_internal.__getitem__.side_effect = lambda k: {
        'users': mock_users_collection,
        'security_events': mock_collection_internal,
        'alerts': mock_alerts_collection
    }.get(k, MagicMock())

    mock_users_collection.find_one.return_value = None
    mock_users_collection.insert_one.return_value.inserted_id = "user_id"
    mock_users_collection.create_index = MagicMock()

    mock_collection_internal.find.return_value = MagicMock(__iter__=lambda self: iter([]))
    mock_collection_internal.insert_one.return_value.inserted_id = "event_id"
    mock_collection_internal.create_index = MagicMock()

    mock_alerts_collection.find.return_value = MagicMock(__iter__=lambda self: iter([]))

    mock_mongo.client = mock_client_internal
    mock_mongo.db = mock_db_internal
    mock_mongo.collection = mock_collection_internal

    mock_mongo.connect = MagicMock()
    mock_mongo.close = MagicMock()

    mock_mongo.create_tables = MagicMock()

    mock_mongo.insert_user.side_effect = lambda u, p: (
        None if mock_users_collection.find_one({"username": u})
        else mock_users_collection.insert_one({"username": u, "password": p}).inserted_id
    )

    mock_mongo.find_by_username.side_effect = lambda u: mock_users_collection.find_one({"username": u})

    mock_mongo.add_event.side_effect = lambda e: (
        None if "invalid-date" in e.get("timestamp", "")
        else mock_collection_internal.insert_one(e).inserted_id
    )

    mock_mongo.get_events.side_effect = lambda **kw: list(mock_collection_internal.find(kw))
    mock_mongo.get_all_events.side_effect = lambda: list(mock_collection_internal.find({}))
    mock_mongo.get_alerts.side_effect = lambda **kw: list(mock_alerts_collection.find(kw))

    return mock_mongo


@pytest.fixture(scope='function')
def mock_report_generator():
    mock = MagicMock(spec=ReportGenerator)
    mock.generate_summary.return_value = {"total_events": 0}
    return mock


@pytest.fixture(scope="function")
def app(mock_sqlite_db_instance, mock_mongo_db_instance, mock_report_generator):

    temp_upload_dir = tempfile.mkdtemp()

    config = {
        'TESTING': True,
        'DATABASE_TYPE': 'sqlite',
        'DATABASE_URI': TEST_DB_PATH,
        'JWT_SECRET_KEY': 'test',
        'UPLOAD_FOLDER': temp_upload_dir,
        'ANOMALIES_THRESHOLD_FACTOR': 2,
        'ANOMALIES_TIME_WINDOW': 3600,
        'ANOMALIES_MIN_EVENTS_FOR_BASELINE': 2,
        'BRUTE_FORCE_THRESHOLD': 5,
        'BRUTE_FORCE_TIME_WINDOW': 300
    }

    # FIX: correct import path (NO logiq.*)
    with patch('utils.config.load_config', return_value=config):

        with patch('db.db_sqlite.SQLiteDatabase', return_value=mock_sqlite_db_instance), \
             patch('db.db_mongo.MongoDB', return_value=mock_mongo_db_instance):

            app_instance = create_app(config=config, db_type='sqlite')
            assert app_instance is not None

            test_app: CustomFlask = app_instance

            test_app.db = mock_sqlite_db_instance

            test_app.detectors = [
                MagicMock(spec=AnomalyDetector),
                MagicMock(spec=BruteForceDetector)
            ]

            for d in test_app.detectors:
                d.detect = MagicMock(return_value=[])

            test_app.report_generator = mock_report_generator

            with test_app.app_context():
                yield test_app

    if os.path.exists(temp_upload_dir):
        shutil.rmtree(temp_upload_dir, ignore_errors=True)


@pytest.fixture(scope="function")
def client(app):
    with app.test_client() as client:
        yield client