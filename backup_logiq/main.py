from __future__ import annotations

import argparse
import logging
import sys
import os
import json
from typing import Union

from flask import Flask, g, jsonify, Response
from flask_jwt_extended import JWTManager
from werkzeug.exceptions import HTTPException, BadRequest

# Imports από το project
from utils.config import load_config
from db.db_sqlite import SQLiteDatabase
from db.db_mongo import MongoDB
from api.routes import api_blueprint
from detectors.anomalies import AnomalyDetector
from detectors.brute_force import BruteForceDetector
from reports.report_generator import ReportGenerator

from jsonschema import ValidationError

logger = logging.getLogger(__name__)

class CustomFlask(Flask):
    """Custom Flask app class."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = None
        self.detectors = []
        self.report_generator = None

def create_app(config: dict = None, db_type: str = None) -> Union[CustomFlask, None]:
    """
    Δημιουργεί και ρυθμίζει την εφαρμογή Flask.
    """
    if config is None:
        config = load_config("config.yaml")

    if config is None:
        logger.critical("Failed to load configuration. Cannot create app.")
        return None

    app = CustomFlask(__name__)
    
    # 1. Φόρτωση ρυθμίσεων
    app.config.from_mapping(config)

    # 2. Ρύθμιση JWT Secret Key
    app.config["JWT_SECRET_KEY"] = app.config.get('JWT_SECRET_KEY') or "super-secret-key"
    
    # 3. Αρχικοποίηση JWT
    JWTManager(app)

    # Register Blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')

    # Database Initialization
    database_type = app.config.get('DATABASE_TYPE', 'mongo')
    mongo_uri = app.config.get('MONGO_URI', 'mongodb://logiq-mongo:27017')
    mongo_db_name = app.config.get('MONGO_DB_NAME', 'logiq')

    try:
        if database_type == 'mongo':
            app.db = MongoDB(mongo_uri, mongo_db_name)
        else:
            database_uri = app.config.get('DATABASE_URI', 'logiq_siem.db')
            app.db = SQLiteDatabase(database_uri)

        if app.db is not None:
            app.db.connect()
            # Στη MongoDB η create_tables συνήθως δημιουργεί indexes
            app.db.create_tables() 
            logger.info(f"Successfully connected to {database_type} database.")
        else:
            logger.error("Database object was not initialized.")
            return None

    except Exception as e:
        logger.critical(f"Failed to connect to database: {e}")
        return None

    # --- ΔΙΟΡΘΩΣΗ: Περνάμε και τη Βάση (app.db) και τις Ρυθμίσεις (app.config) ---
    # Αυτό αποτρέπει το AttributeError: 'MongoDB' object has no attribute 'get'
    app.detectors = [
        AnomalyDetector(app.db, app.config),
        BruteForceDetector(app.db, app.config)
    ]
    # -------------------------------------------------------------------------

    app.report_generator = ReportGenerator(app.config)

    # Error Handlers
    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        return jsonify({"error": e.description or str(e)}), e.code

    @app.errorhandler(Exception)
    def handle_general_exception(e):
        if isinstance(e, ValidationError):
            return jsonify({"error": e.message}), 422
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        return jsonify({"error": "An internal server error occurred"}), 500

    return app

def main():
    """Κύριο σημείο εισόδου."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    parser = argparse.ArgumentParser(description="Logiq SIEM Application")
    parser.add_argument('--mode', type=str, choices=['server', 'cli'], default='server')
    args = parser.parse_args()

    if args.mode == 'server':
        app = create_app()
        if app is not None:
            logger.info("Starting Flask server on port 5000...")
            # Το host 0.0.0.0 είναι απαραίτητο για το Docker
            app.run(debug=True, host='0.0.0.0', port=5000)
        else:
            logger.critical("App creation failed. Exiting.")
            sys.exit(1)

if __name__ == '__main__':
    main()