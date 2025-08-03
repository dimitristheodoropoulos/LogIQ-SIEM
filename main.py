from __future__ import annotations

import argparse
import logging
import sys
import os
import json # Import json for manual response creation
from typing import Union # Explicitly import Union for Python 3.8 compatibility

from flask import Flask, g, jsonify, Response # Import Response
from flask_jwt_extended import JWTManager
from werkzeug.exceptions import HTTPException, BadRequest # Import BadRequest explicitly for clarity

# Import necessary modules from your project
from logiq.utils.config import load_config
from logiq.db.db_sqlite import SQLiteDatabase
from logiq.db.db_mongo import MongoDB
from logiq.api.routes import api_blueprint
from logiq.detectors.anomalies import AnomalyDetector
from logiq.detectors.brute_force import BruteForceDetector
from logiq.reports.report_generator import ReportGenerator

# Import ValidationError from jsonschema for the error handler
from jsonschema import ValidationError


logger = logging.getLogger(__name__)

class CustomFlask(Flask):
    """Custom Flask app class to hold database and detectors."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = None
        self.detectors = []
        self.report_generator = None # Initialize report_generator

def create_app(config: dict = None, db_type: str = None) -> Union[CustomFlask, None]:
    """
    Creates and configures the Flask application.

    Args:
        config (dict, optional): A dictionary of configuration settings.
                                 If None, configuration is loaded from file.
        db_type (str, optional): Overrides the database type specified in config.

    Returns:
        CustomFlask: The configured Flask application instance.
        None: If there's a critical error during app creation (e.g., DB connection).
    """
    if config is None:
        config = load_config()

    # If config is still None after loading, something is fundamentally wrong
    if config is None:
        logger.critical("Failed to load configuration. Cannot create app.")
        return None

    app = CustomFlask(__name__)
    app.config.from_mapping(config)

    # Initialize JWTManager
    # Use JWT_SECRET_KEY from config if available, otherwise fallback to SECRET_KEY, then a default
    app.config["JWT_SECRET_KEY"] = app.config.get('JWT_SECRET_KEY') or app.config.get('SECRET_KEY', 'super-secret')
    JWTManager(app)

    # Register blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')

    # Initialize database
    database_type = db_type or app.config.get('DATABASE_TYPE', 'sqlite')
    database_uri = app.config.get('DATABASE_URI', 'logiq_siem.db')
    mongo_uri = app.config.get('MONGO_URI', 'mongodb://localhost:27017/')
    mongo_db_name = app.config.get('MONGO_DB_NAME', 'logiq_siem')

    try:
        if database_type == 'sqlite':
            app.db = SQLiteDatabase(database_uri)
        elif database_type == 'mongo':
            app.db = MongoDB(mongo_uri, mongo_db_name)
        else:
            logger.error(f"Unsupported database type: {database_type}")
            return None

        app.db.connect()
        # create_tables is a no-op for MongoDB, handled internally by db_mongo.py
        # For SQLite, it ensures tables exist.
        app.db.create_tables() 
        logger.info(f"Connected to {database_type} database.")
    except Exception as e:
        logger.critical(f"Failed to connect to database: {e}")
        app.db = None # Ensure db is None on failure
        return None

    # Initialize detectors
    app.detectors = [
        AnomalyDetector(app.config),
        BruteForceDetector(app.config)
    ]
    logger.info("Security detectors initialized.")

    # Initialize ReportGenerator
    # ReportGenerator should be initialized with the app.config, not an empty list
    app.report_generator = ReportGenerator(app.config)

    # Generic error handler for HTTP exceptions
    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        # Create a JSON response object manually to ensure mimetype is set
        response_data = {"error": e.description or str(e)}
        response = Response(json.dumps(response_data), mimetype='application/json')
        response.status_code = e.code
        return response

    # Generic error handler for all other exceptions
    @app.errorhandler(Exception)
    def handle_general_exception(e):
        # Handle validation errors specifically if they are not HTTPExceptions
        if isinstance(e, ValidationError):
            logger.error(f"Validation Error: {e.message}")
            return jsonify({"error": e.message}), 422

        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        return jsonify({"error": "An internal server error occurred"}), 500

    return app

def main():
    """Main entry point for the Logiq SIEM application."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    parser = argparse.ArgumentParser(description="Logiq SIEM Application")
    parser.add_argument('--mode', type=str, choices=['server', 'cli'], default='server',
                        help="Run mode: 'server' for Flask app, 'cli' for command-line interface.")
    parser.add_argument('--cli-command', type=str,
                        choices=['parse-logs', 'alerts', 'report', 'db-test'],
                        help="CLI command to run (required if --mode is 'cli').")
    parser.add_argument('--time-window', type=str,
                        help="Time window for reports (e.g., '1h', '24h', '7d'). Required for 'report' command.")

    args = parser.parse_args()

    if args.mode == 'server':
        app = create_app()
        if app:
            logger.info("Starting Flask server...")
            app.run(debug=True)
        else:
            logger.critical("Failed to start Flask server due to app creation error.")
            sys.exit(1)
    elif args.mode == 'cli':
        from logiq.cli.runner import run_cli_command
        app = create_app()
        if app:
            logger.info(f"Running CLI command: {args.cli_command}")
            run_cli_command(app, args.cli_command, args.time_window)
            if app.db: # Ensure db exists before trying to close
                app.db.close() # Close DB connection after CLI command
        else:
            logger.critical("Failed to run CLI command due to app creation error.")
            sys.exit(1)

if __name__ == '__main__':
    main()
