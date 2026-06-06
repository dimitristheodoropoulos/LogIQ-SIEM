from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, create_access_token
from datetime import datetime, timedelta, timezone
import logging
import os 
from elasticsearch import Elasticsearch
from functools import wraps

logger = logging.getLogger(__name__)
api_blueprint = Blueprint('api', __name__)

MASTER_API_KEY = "LOGIQ_SUPER_SECRET_KEY_2026"

# Elasticsearch setup
try:
    es = Elasticsearch([os.getenv('ELASTICSEARCH_URL', 'http://logiq-elastic:9200')])
except:
    es = None

def secure_access(f):
    """
    Decorator που επιτρέπει πρόσβαση είτε με Master API Key (X-API-KEY header)
    είτε με έγκυρο JWT Token.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-KEY')
        
        # 1. Έλεγχος Master Key
        if api_key == MASTER_API_KEY:
            return f(*args, **kwargs)
        
        # 2. Έλεγχος JWT Token (Χρησιμοποιούμε τη σωστή σύνταξη)
        @jwt_required()
        def wrapper():
            return f(*args, **kwargs)
            
        return wrapper()
        
    return decorated_function

# --- ENDPOINT: LOGIN ---
@api_blueprint.route('/login', methods=['POST'])
def login():
    """Εκδίδει JWT Token για τον collector"""
    data = request.get_json()
    if not data:
        return jsonify({"msg": "Missing JSON in request"}), 400
        
    username = data.get('username')
    password = data.get('password')

    # Έλεγχος στοιχείων (admin/admin ή master key)
    if (username == 'admin' and password == 'admin') or (username == 'master' and password == MASTER_API_KEY):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    
    return jsonify({"msg": "Bad username or password"}), 401

# --- ENDPOINT: ALERTS ---
@api_blueprint.route('/alerts', methods=['GET'])
@secure_access
def get_alerts():
    try:
        events = current_app.db.get_events()
        detected_alerts = []
        
        for e in events:
            msg = str(e.get('message', '')).upper()
            etype = str(e.get('event_type', '')).lower()
            severity = str(e.get('severity', '')).lower()
            
            if (severity in ['critical', 'high'] or 
                'SELECT' in msg or 'UNION' in msg or 
                etype in ['sql_injection', 'unauthorized_access', 'brute_force']):
                
                detected_alerts.append({
                    "alert_id": str(e.get('_id')),
                    "message": e.get('message', 'Security Threat'),
                    "severity": e.get('severity', 'critical'),
                    "alert_type": e.get('event_type', 'Intrusion'),
                    "source_ip": e.get('source_ip') or e.get('ip') or 'N/A',
                    "timestamp": e.get('timestamp')
                })
        
        return jsonify({"alerts": detected_alerts, "status": "success"}), 200
    except Exception as e:
        logger.error(f"Alert error: {e}")
        return jsonify({"error": str(e), "alerts": []}), 500

# --- ENDPOINT: EVENTS (POST) ---
@api_blueprint.route('/events', methods=['POST'])
@secure_access
def add_security_events():
    try:
        events_data = request.get_json()
        if not events_data:
            return jsonify({"error": "No data provided"}), 400

        if not isinstance(events_data, list):
            events_data = [events_data]
            
        added_count = 0
        for event_data in events_data:
            # Αποθήκευση στη MongoDB
            event_id = current_app.db.add_event(event_data)
            if event_id:
                added_count += 1
                
        return jsonify({"status": "success", "added": added_count}), 201
    except Exception as e:
        logger.error(f"❌ Critical Error in add_security_events: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# --- ENDPOINT: GET ALL EVENTS ---
@api_blueprint.route('/events/all', methods=['GET'])
@secure_access
def get_all_events():
    events = current_app.db.get_events()
    for e in events:
        if '_id' in e: e['_id'] = str(e['_id'])
    return jsonify(events), 200