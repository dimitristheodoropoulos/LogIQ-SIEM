from __future__ import annotations

from jsonschema import FormatChecker

# Initialize FormatChecker for date-time format validation
format_checker = FormatChecker()

user_register_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string", "minLength": 3},
        "password": {"type": "string", "minLength": 8}
    },
    "required": ["username", "password"]
}

security_event_schema = {
    "type": "object",
    "properties": {
        "timestamp": {"type": "string", "format": "date-time"},
        "hostname": {"type": "string"},
        "event_type": {"type": "string"},
        "process": {"type": ["string", "null"]},
        "message": {"type": "string"},
        "ip": {"type": ["string", "null"]},
        "details": {"type": ["object", "null"]}
    },
    "required": ["timestamp", "hostname", "event_type", "message"],
    "additionalProperties": False
}
