from flask import Blueprint, request, jsonify, current_app, send_file
from flask_jwt_extended import create_access_token, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash
from jsonschema import validate, ValidationError
import os
import json
from datetime import datetime, timezone

try:
    from api.schemas import security_event_schema, user_register_schema, format_checker
except ImportError:
    # Fallback αν δεν βρεθούν τα schemas (χρήσιμο για tests)
    user_register_schema = {
        "type": "object", 
        "required": ["username", "password"], 
        "properties": {
            "username": {"type": "string"}, 
            "password": {"type": "string", "minLength": 6}
        }
    }
    security_event_schema = {
        "type": "object", 
        "required": ["timestamp", "event_type"], 
        "properties": {
            "timestamp": {"type": "string", "format": "date-time"}, 
            "event_type": {"type": "string"}
        }, 
        "additionalProperties": False
    }
    from jsonschema import FormatChecker
    format_checker = FormatChecker()

api_blueprint = Blueprint("api", __name__)

def export_logs_function(events, fmt, filename, directory=None):
    """Βοηθητική συνάρτηση για την εγγραφή των logs στο δίσκο."""
    if directory:
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, filename)
    else:
        path = filename
    
    with open(path, 'w', encoding='utf-8') as f:
        if fmt == 'json':
            json.dump(events, f)
        elif fmt == 'csv':
            import csv
            writer = csv.writer(f)
            if events:
                writer.writerow(events[0].keys())
                for e in events:
                    writer.writerow(e.values())
        else:
            f.write(str(events))
    return path

@api_blueprint.route("/", methods=["GET"])
def index():
    return jsonify({"status": "success", "message": "Welcome to LogIQ SIEM API"}), 200

@api_blueprint.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    try:
        validate(instance=data, schema=user_register_schema, format_checker=format_checker)
    except ValidationError as e:
        return jsonify({"error": f"Schema validation error: {e.message}"}), 422

    username = data.get("username")
    password = data.get("password")

    if current_app.db.find_by_username(username):
        return jsonify({"error": "Το όνομα χρήστη υπάρχει ήδη", "status": "error"}), 409

    hashed = generate_password_hash(password)
    user_id = current_app.db.insert_user(username, hashed)
    return jsonify({"message": "Επιτυχής εγγραφή χρήστη", "status": "success", "user_id": user_id}), 201

@api_blueprint.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    user = current_app.db.find_by_username(username)
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Λανθασμένο όνομα χρήστη ή κωδικός"}), 401

    access_token = create_access_token(identity=username)
    return jsonify({"access_token": access_token, "status": "success"}), 200

@api_blueprint.route("/events", methods=["POST"])
@jwt_required()
def add_events():
    data = request.get_json()
    if not data:
        return jsonify({"message": "No data"}), 400
    
    events = data if isinstance(data, list) else [data]
    try:
        for e in events:
            validate(instance=e, schema=security_event_schema, format_checker=format_checker)
    except ValidationError as e:
        return jsonify({"error": e.message}), 400

    for e in events:
        current_app.db.add_event(e)
    return jsonify({"message": "Events added successfully", "status": "success", "added": len(events)}), 201

@api_blueprint.route("/alerts", methods=["GET"])
@jwt_required()
def get_alerts():
    alerts = current_app.db.get_alerts()
    enriched_alerts = []
    for a in alerts:
        a_copy = dict(a)
        a_copy["mitre_info"] = "T1078 - Valid Accounts"
        enriched_alerts.append(a_copy)
    
    return jsonify({"status": "success", "alerts": enriched_alerts}), 200

@api_blueprint.route("/report", methods=["POST"])
@jwt_required()
def generate_report():
    data = request.get_json() or {}
    window = data.get("time_window", "24h")
    if window not in ["1h", "24h", "7d"]:
        return jsonify({"error": "Unsupported window"}), 400
        
    events = current_app.db.get_all_events()
    # ΔΙΟΡΘΩΣΗ: Πέρασμα των events στη μέθοδο της report_generator
    summary = current_app.report_generator.generate_summary(window, events)
    return jsonify({"status": "success", "summary": summary}), 200

@api_blueprint.route("/export", methods=["GET"])
@jwt_required()
def export_logs():
    fmt = request.args.get("format", "json")
    if fmt not in ["json", "csv", "pdf"]:
        return jsonify({"error": "Unsupported format"}), 400
        
    events = current_app.db.get_all_events()
    # ΔΙΟΡΘΩΣΗ: Χρήση timezone-aware datetime για το filename
    filename = f"export_{int(datetime.now(timezone.utc).timestamp())}.{fmt}"
    directory = current_app.config.get('UPLOAD_FOLDER', './')
    
    path = export_logs_function(events, fmt, filename, directory=directory)
    
    return send_file(path, as_attachment=True)