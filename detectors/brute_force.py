from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Union

logger = logging.getLogger(__name__)

class BruteForceDetector:
    """
    Detects brute force attacks based on a high number of failed login attempts
    for a specific user or IP within a defined time window.
    """
    def __init__(self, config: Dict):
        self.config = config
        self.threshold = config.get('BRUTE_FORCE_THRESHOLD', 5)  # Number of failed attempts
        self.time_window = config.get('BRUTE_FORCE_TIME_WINDOW', 300) # in seconds (5 minutes)
        logging.info(f"BruteForceDetector initialized with threshold: {self.threshold}, time window: {self.time_window}s")

    def detect(self, events: List[Dict]) -> List[Dict]:
        """
        Detects brute force attempts in a list of security events.
        
        :param events: A list of event dictionaries.
        :return: A list of dictionaries, each representing a detected brute force alert.
        """
        logging.info(f"Starting brute force detection on {len(events)} events.")
        
        failed_logins_by_user_ip = defaultdict(list)
        alerts = []
        now = datetime.utcnow()

        for event in events:
            timestamp_str = event.get('timestamp')
            if isinstance(timestamp_str, str):
                try:
                    event_timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    event['timestamp_dt'] = event_timestamp
                except ValueError:
                    logging.warning(f"Invalid timestamp format for event: {timestamp_str}. Skipping event.")
                    continue
            else:
                logging.warning(f"Missing or invalid timestamp type for event: {timestamp_str}. Skipping event.")
                continue

            event_type = event.get('event_type')
            username = event.get('username') # FIX: Access 'username' directly
            ip = event.get('ip') # FIX: Access 'ip' directly

            if event_type and 'fail' in event_type.lower() and username and ip:
                failed_logins_by_user_ip[(username, ip)].append(event)
        
        for (username, ip), failed_attempts_list in failed_logins_by_user_ip.items():
            recent_failed_attempts = [
                attempt for attempt in failed_attempts_list
                if attempt['timestamp_dt'] >= (now - timedelta(seconds=self.time_window))
            ]
            
            if len(recent_failed_attempts) >= self.threshold:
                recent_failed_attempts.sort(key=lambda x: x['timestamp_dt'], reverse=True)
                last_attempt_time = recent_failed_attempts[0]['timestamp_dt'].isoformat()

                alert_data = {
                    "alert_type": "brute_force",
                    "username": username,
                    "ip": ip,
                    "fail_count": len(recent_failed_attempts),
                    "last_attempt": last_attempt_time,
                    "timestamp": now.isoformat(),
                    "message": (
                        f"Brute force attempt detected for user '{username}' from IP '{ip}'. "
                        f"({len(recent_failed_attempts)} failed attempts within {self.time_window} seconds)."
                    )
                }
                alerts.append(alert_data)
                logging.warning(f"Brute force alert generated: {alert_data}")
        
        logging.info(f"Brute force detection finished. Found {len(alerts)} alerts.")
        return alerts
