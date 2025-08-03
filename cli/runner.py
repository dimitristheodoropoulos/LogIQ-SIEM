from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from logiq.main import CustomFlask

from logiq.db.db_sqlite import SQLiteDatabase
from logiq.parsers.auth_parser import parse_auth_log
from logiq.log_collector_linux import get_auth_token, send_events
from logiq.detectors.anomalies import AnomalyDetector
from logiq.detectors.brute_force import BruteForceDetector
from logiq.reports.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

def run_parse_logs(app: CustomFlask):
    """Parses logs from the configured log file and inserts them into the database."""
    log_file_path = app.config.get('LOG_FILE_PATH')
    if not log_file_path:
        logger.error("LOG_FILE_PATH not configured.")
        return

    logger.info(f"Parsing logs from {log_file_path}...")
    try:
        events = parse_auth_log(log_file_path)
        if events:
            db_instance = app.db
            for event in events:
                db_instance.add_event(event)
            logger.info(f"Εισήχθησαν {len(events)} events στη βάση δεδομένων.")
            print(f"Εισήχθησαν {len(events)} events στη βάση δεδομένων.")
        else:
            logger.info("Δεν βρέθηκαν νέα events για εισαγωγή.")
            print("Δεν βρέθηκαν νέα events για εισαγωγή.")
    except Exception as e:
        logger.error(f"Σφάλμα κατά την ανάλυση ή εισαγωγή logs: {e}", exc_info=True)
        print(f"Σφάλμα κατά την ανάλυση ή εισαγωγή logs: {e}")

def run_alerts(app: CustomFlask):
    """Runs all configured detectors and displays active alerts."""
    logger.info("Εκτέλεση ανιχνευτών ειδοποιήσεων...")
    alerts = []
    
    db_instance = app.db
    all_events = db_instance.get_all_events()

    if not all_events:
        logger.info("Δεν υπάρχουν events στη βάση δεδομένων για ανάλυση ειδοποιήσεων.")
        print("Δεν βρέθηκαν ενεργές ειδοποιήσεις.")
        return

    for detector in app.detectors:
        try:
            detected_alerts = detector.detect(all_events)
            alerts.extend(detected_alerts)
        except Exception as e:
            logger.error(f"Σφάλμα κατά την εκτέλεση του ανιχνευτή {detector.__class__.__name__}: {e}", exc_info=True)

    if alerts:
        print("\nΕνεργές Ειδοποιήσεις:")
        for alert in alerts:
            print(f"- Τύπος: {alert.get('alert_type', 'Άγνωστος')}, "
                  f"Συμβάν: {alert.get('event_type', 'Άγνωστο')}, "
                  f"Χρήστης: {alert.get('username', 'N/A')}, "
                  f"IP: {alert.get('ip', 'N/A')}, "
                  f"Μήνυμα: {alert.get('message', 'N/A')}, "
                  f"Ώρα: {alert.get('timestamp', 'N/A')}")
    else:
        print("Δεν βρέθηκαν ενεργές ειδοποιήσεις.")
    logger.info("Ολοκληρώθηκε η εκτέλεση ανιχνευτών ειδοποιήσεων.")

def run_report(app: CustomFlask, time_window: str):
    """Generates and displays a security report."""
    logger.info(f"Δημιουργία αναφοράς για {time_window}...")
    try:
        db_instance = app.db
        all_events = db_instance.get_all_events()
        # Ensure events are converted to dictionaries if they are sqlite3.Row objects
        events_dicts = [dict(row) for row in all_events]

        # Initialize ReportGenerator with app.config, not events_dicts
        report_generator = app.report_generator
        summary = report_generator.generate_summary(time_window, events_dicts) # Pass events to generate_summary

        if "error" in summary:
            print(f"Σφάλμα κατά τη δημιουργία αναφοράς: {summary['error']}")
            logger.error(f"Failed to generate report: {summary['error']}")
        else:
            print("Η αναφορά δημιουργήθηκε επιτυχώς.")
            print("\nΣύνοψη αναφοράς:")
            for key, value in summary.items():
                print(f"- {key.replace('_', ' ').title()}: {value}")
    except Exception as e:
        logger.error(f"Σφάλμα κατά τη δημιουργία αναφοράς: {e}", exc_info=True)
        print(f"Σφάλμα κατά τη δημιουργία αναφοράς: {e}")

def run_db_connection_test(app: CustomFlask):
    """Tests the database connection."""
    logger.info("Δοκιμή σύνδεσης βάσης δεδομένων...")
    try:
        # Check if app.db exists and if its connect method can be called without error
        # The app.db.conn check might be specific to SQLite. For MongoDB, app.db.client might be more appropriate.
        # A more robust check would be to call a simple DB operation like app.db.ping() if available.
        app.db.connect() # Re-attempt connection to verify
        if app.db.conn: # This check is for SQLite. For MongoDB, you might check app.db.client
            print("Επιτυχής σύνδεση με τη βάση δεδομένων.")
            logger.info("Database connection test successful.")
        else:
            # This path might be taken if connect() didn't raise an exception but also didn't set conn
            logger.error("Αδύνατη η σύνδεση με τη βάση δεδομένων: Η σύνδεση είναι None.")
            print("Κρίσιμο σφάλμα: Αδύνατη η σύνδεση με τη βάση δεδομένων: Η σύνδεση είναι None.")
            sys.exit(1)
    except Exception as e:
        logger.critical(f"Κρίσιμο σφάλμα: Αδύνατη η σύνδεση με τη βάση δεδομένων. {e}", exc_info=True)
        print(f"Κρίσιμο σφάλμα: Αδύνατη η σύνδεση με τη βάση δεδομένων. {e}")
        sys.exit(1)

def run_cli_command(app: CustomFlask, command: str, time_window: Union[str, None] = None):
    """Dispatches CLI commands."""
    if command == 'parse-logs':
        run_parse_logs(app)
    elif command == 'alerts':
        run_alerts(app)
    elif command == 'report':
        if time_window:
            run_report(app, time_window)
        else:
            print("Error: --time-window is required for 'report' command.")
            sys.exit(1)
    elif command == 'db-test':
        run_db_connection_test(app)
    else:
        print(f"Unknown CLI command: {command}")
        sys.exit(1)
