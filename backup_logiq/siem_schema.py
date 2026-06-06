from datetime import datetime, timezone
from typing import Dict, Any


def create_alert(
    alert_type: str,
    severity: str,
    message: str,
    event_type: str = None,
    username: str = None,
    source: str = None,
    details: Dict[str, Any] = None
):
    return {
        "alert_type": alert_type,
        "severity": severity,
        "message": message,
        "event_type": event_type,
        "username": username,
        "source": source,
        "details": details or {},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }