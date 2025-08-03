from flask import Blueprint, request, jsonify, current_app, send_file
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from jsonschema import validate, ValidationError
from datetime import datetime, timedelta
import logging
import os # Import os for file operations
import json # Import json for loading details
from typing import Union # Import Union for type hinting compatibility

# Import schemas and the format_checker
from logiq.api.schemas import security_event_schema, user_register_schema, format_checker

# Assuming these are available in the current_app context
# from logiq.detectors.anomalies import AnomalyDetector
# from logiq.detectors.brute_force import BruteForceDetector
# from logiq.reports.report_generator import ReportGenerator
from logiq.export_logs import export_logs as export_logs_function # Alias to avoid name conflict

logger = logging.getLogger(__name__)

api_blueprint = Blueprint('api', __name__)

@api_blueprint.route('/')
def index():
    return jsonify({"message": "Welcome to the Logiq SIEM API!"})

@api_blueprint.route('/register', methods=['POST'])
def register_user():
    user_data = request.get_json()
    if not user_data:
        return jsonify({"error": "Invalid JSON"}), 400
    
    try:
        validate(instance=user_data, schema=user_register_schema, format_checker=format_checker)
    except ValidationError as e:
        return jsonify({"error": e.message}), 422

    username = user_data.get('username')
    password = user_data.get('password')

    hashed_password = generate_password_hash(password)

    try:
        # Check if user already exists before attempting to insert
        existing_user = current_app.db.find_by_username(username)
        if existing_user:
            return jsonify({"error": "Το όνομα χρήστη υπάρχει ήδη"}), 409 # 409 Conflict
        
        user_id = current_app.db.insert_user(username, hashed_password)
        if user_id:
            return jsonify({"message": "Επιτυχής εγγραφή χρήστη", "user_id": user_id}), 201
        else:
            # This branch should ideally not be reached if existing_user check works
            return jsonify({"error": "Αποτυχία εγγραφής χρήστη"}), 500 
    except Exception as e:
        logger.error(f"Error registering user: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@api_blueprint.route('/login', methods=['POST'])
def login_user():
    user_data = request.get_json()
    if not user_data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = user_data.get('username')
    password = user_data.get('password')

    user = current_app.db.find_by_username(username)

    if user and check_password_hash(user['password'], password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"error": "Λανθασμένο όνομα χρήστη ή κωδικός"}), 401

@api_blueprint.route('/events', methods=['POST'])
@jwt_required()
def add_security_events():
    events_data = request.get_json()
    if not isinstance(events_data, list):
        return jsonify({"error": "Payload must be a list of events"}), 400

    added_events = []
    for event_data in events_data:
        try:
            # IMPORTANT: Pass format_checker to validate for date-time format enforcement
            validate(instance=event_data, schema=security_event_schema, format_checker=format_checker)
            event_id = current_app.db.add_event(event_data)
            if event_id:
                added_events.append({"id": event_id, **event_data})
        except ValidationError as e:
            logger.error(f"Schema validation error: {e.message}")
            return jsonify({"error": f"Invalid event data: {e.message}"}), 422
        except Exception as e:
            logger.error(f"Error adding event: {e}", exc_info=True)
            return jsonify({"error": "Internal server error adding event"}), 500
    
    return jsonify({"message": "Events added successfully", "events": added_events}), 201

@api_blueprint.route('/alerts', methods=['GET'])
@jwt_required()
def get_alerts():
    threshold_str = request.args.get('threshold')
    time_window_str = request.args.get('time_window')

    if not threshold_str:
        return jsonify({"error": "Missing 'threshold' parameter"}), 400
    if not time_window_str:
        return jsonify({"error": "Missing 'time_window' parameter"}), 400

    try:
        threshold = int(threshold_str)
    except ValueError:
        return jsonify({"error": "Invalid 'threshold' parameter. Must be an integer."}), 400

    # Parse time_window (e.g., "1h", "24h", "7d")
    if not time_window_str or len(time_window_str) < 2:
        return jsonify({"error": "Invalid 'time_window' format. Use 'h' for hours or 'd' for days (e.g., '24h', '7d')."}), 400

    time_unit = time_window_str[-1]
    try:
        time_value = int(time_window_str[:-1])
    except ValueError:
        return jsonify({"error": "Invalid 'time_window' value. Numeric part is invalid."}), 400

    end_time = datetime.utcnow()
    if time_unit == 'h':
        start_time = end_time - timedelta(hours=time_value)
    elif time_unit == 'd':
        start_time = end_time - timedelta(days=time_value)
    else:
        return jsonify({"error": "Invalid 'time_window' unit. Use 'h' for hours or 'd' for days."}), 400

    try:
        # Fetch events within the time window from the database
        # Assuming get_events can filter by start_date and end_date
        all_events_in_window = current_app.db.get_events(start_date=start_time, end_date=end_time)
        
        # Convert sqlite3.Row objects to dictionaries for detectors
        events_for_detectors = []
        for event_row in all_events_in_window:
            event_dict = dict(event_row)
            # Deserialize 'details' if it's a JSON string
            if 'details' in event_dict and event_dict['details'] is not None:
                try:
                    event_dict['details'] = json.loads(event_dict['details'])
                except json.JSONDecodeError:
                    logger.warning(f"Could not decode details for event ID {event_dict.get('id')}: {event_dict['details']}")
            events_for_detectors.append(event_dict)


        detected_alerts = []
        for detector in current_app.detectors:
            alerts_from_detector = detector.detect(events_for_detectors)
            detected_alerts.extend(alerts_from_detector)
        
        # Filter alerts based on threshold (e.g., only return alerts if total count >= threshold)
        # This logic might need to be more sophisticated depending on alert types
        final_alerts = [alert for alert in detected_alerts if len(detected_alerts) >= threshold] # Simplified filtering

        return jsonify({"alerts": final_alerts}), 200
    except Exception as e:
        logger.error(f"Error getting alerts: {e}", exc_info=True)
        return jsonify({"error": "Internal server error retrieving alerts"}), 500

@api_blueprint.route('/report', methods=['POST'])
@jwt_required()
def generate_report():
    report_data = request.get_json()
    if not report_data:
        return jsonify({"error": "Invalid JSON"}), 400

    time_window = report_data.get('time_window')

    if not time_window:
        return jsonify({"error": "Missing 'time_window' parameter for report generation"}), 400

    try:
        # Fetch all events from the database
        all_events = current_app.db.get_all_events()
        
        # Convert sqlite3.Row objects to dictionaries for the report generator
        events_for_report = []
        for event_row in all_events:
            event_dict = dict(event_row)
            if 'details' in event_dict and event_dict['details'] is not None:
                try:
                    event_dict['details'] = json.loads(event_dict['details'])
                except json.JSONDecodeError:
                    logger.warning(f"Could not decode details for event ID {event_dict.get('id')}: {event_dict['details']}")
            events_for_report.append(event_dict)

        # Generate report using the ReportGenerator attached to the app
        # The ReportGenerator expects a list of event dictionaries
        report_summary = current_app.report_generator.generate_summary(time_window, events_for_report) # Pass events to generator
        return jsonify({"summary": report_summary}), 200
    except Exception as e:
        logger.error(f"Error generating report: {e}", exc_info=True)
        return jsonify({"error": "Internal server error generating report"}), 500

# Helper function for report export (moved from test_report_export.py for clarity)
def _export_report_summary(report_data: dict, format_type: str, filename_prefix: str, directory: str) -> Union[str, None]:
    """
    Helper function to export report summary to a file.
    This is a simplified mock for testing purposes. In a real app, this would
    likely involve a more robust report generation library (e.g., ReportLab for PDF).
    """
    file_path = os.path.join(directory, f"{filename_prefix}.{format_type}")
    try:
        if format_type == 'json':
            with open(file_path, 'w') as f:
                json.dump(report_data, f, indent=4)
        elif format_type == 'pdf':
            # Simulate PDF creation by writing a dummy PDF header
            with open(file_path, 'wb') as f:
                f.write(b"%PDF-1.4\n%%EOF")
        else:
            logger.error(f"Unsupported report export format: {format_type}")
            return None
        return file_path
    except Exception as e:
        logger.error(f"Error exporting report summary to {format_type}: {e}", exc_info=True)
        return None

@api_blueprint.route('/report/export', methods=['GET']) # Changed to GET and added /export
@jwt_required()
def export_report_route():
    format_type = request.args.get('format')
    time_window = request.args.get('time_window')

    if not format_type:
        return jsonify({"error": "Missing 'format' parameter"}), 400
    if not time_window:
        return jsonify({"error": "Missing 'time_window' parameter"}), 400

    if format_type not in ['json', 'pdf']: # Only support json and pdf for reports
        return jsonify({"error": f"Unsupported report format: {format_type}. Supported formats are 'json', 'pdf'."}), 400

    try:
        # Fetch all events from the database
        all_events = current_app.db.get_all_events()
        
        # Convert sqlite3.Row objects to dictionaries for the report generator
        events_for_report = []
        for event_row in all_events:
            event_dict = dict(event_row)
            if 'details' in event_dict and event_dict['details'] is not None:
                try:
                    event_dict['details'] = json.loads(event_dict['details'])
                except json.JSONDecodeError:
                    logger.warning(f"Could not decode details for event ID {event_dict.get('id')}: {event_dict['details']}")
            events_for_report.append(event_dict)

        # Generate report summary
        report_summary = current_app.report_generator.generate_summary(time_window, events_for_report)
        
        # Combine summary and events data for export
        full_report_data = {
            "summary": report_summary,
            "events_data": events_for_report
        }

        # Use a temporary file to store the export
        temp_filename_prefix = f"report_summary_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        exported_file_path = _export_report_summary(full_report_data, format_type, temp_filename_prefix, current_app.config['UPLOAD_FOLDER'])
        
        if exported_file_path and os.path.exists(exported_file_path):
            mimetype = 'application/json' if format_type == 'json' else 'application/pdf'
            return send_file(exported_file_path, mimetype=mimetype, as_attachment=True, download_name=f"report_summary.{format_type}")
        else:
            return jsonify({"error": "Failed to generate report file."}), 500
    except Exception as e:
        logger.error(f"Error exporting report: {e}", exc_info=True)
        return jsonify({"error": "Internal server error exporting report"}), 500


@api_blueprint.route('/events/all', methods=['GET'])
@jwt_required()
def get_all_events():
    """Retrieves all security events from the database."""
    try:
        all_events = current_app.db.get_all_events()
        # Convert sqlite3.Row objects to dictionaries if necessary
        events_dicts = []
        for event_row in all_events:
            event_dict = dict(event_row)
            if 'details' in event_dict and event_dict['details'] is not None:
                try:
                    event_dict['details'] = json.loads(event_dict['details'])
                except json.JSONDecodeError:
                    logger.warning(f"Could not decode details for event ID {event_dict.get('id')}: {event_dict['details']}")
            events_dicts.append(event_dict)
        return jsonify({"events": events_dicts}), 200
    except Exception as e:
        logger.error(f"Error getting all events: {e}", exc_info=True)
        return jsonify({"error": "Internal server error retrieving all events"}), 500

@api_blueprint.route('/events', methods=['GET'])
@jwt_required()
def get_events_with_filters():
    """Retrieves security events with optional filters."""
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    hostname = request.args.get('hostname')
    event_type = request.args.get('event_type')
    ip = request.args.get('ip')

    # Convert date strings to datetime objects if provided
    start_date = None
    end_date = None
    if start_date_str:
        try:
            start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
        except ValueError:
            return jsonify({"error": "Invalid 'start_date' format. Use ISO 8601 (e.g., 2023-01-01T12:00:00Z)."}), 400
    if end_date_str:
        try:
            end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
        except ValueError:
            return jsonify({"error": "Invalid 'end_date' format. Use ISO 8601 (e.g., 2023-01-01T12:00:00Z)."}), 400

    try:
        filtered_events = current_app.db.get_events(
            start_date=start_date,
            end_date=end_date,
            hostname=hostname,
            event_type=event_type,
            ip=ip
        )
        # Convert sqlite3.Row objects to dictionaries if necessary
        events_dicts = []
        for event_row in filtered_events:
            event_dict = dict(event_row)
            if 'details' in event_dict and event_dict['details'] is not None:
                try:
                    event_dict['details'] = json.loads(event_dict['details'])
                except json.JSONDecodeError:
                    logger.warning(f"Could not decode details for event ID {event_dict.get('id')}: {event_dict['details']}")
            events_dicts.append(event_dict)
        return jsonify({"events": events_dicts}), 200
    except Exception as e:
        logger.error(f"Error getting filtered events: {e}", exc_info=True)
        return jsonify({"error": "Internal server error retrieving filtered events"}), 500
