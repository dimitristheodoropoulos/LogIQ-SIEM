from collections import defaultdict
from typing import List, Dict
from siem_schema import create_alert


class BruteForceDetector:
    def __init__(self, db=None, config: Dict = None):
        self.db = db or {}
        config = config or {}

        self.threshold = config.get("BRUTE_FORCE_THRESHOLD", 5)
        self.time_window = config.get("BRUTE_FORCE_TIME_WINDOW", 300)

    def detect(self, events: List[Dict]) -> List[Dict]:
        if not events:
            return []

        failed_by_user = defaultdict(list)
        alerts = []

        # group failed logins
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            username = event.get("username")
            ip = event.get("ip")

            if "fail" in event_type and username:
                failed_by_user[username].append(event)

        # evaluate per user
        for username, attempts in failed_by_user.items():
            if len(attempts) >= self.threshold:
                last_attempt = attempts[-1]

                alert = create_alert(
                    alert_type="brute_force",
                    severity="high",
                    message=f"Brute force detected for user {username}",
                    event_type="authentication_failure",
                    username=username,
                    source="brute_force_detector",
                    details={
                        "fail_count": len(attempts)
                    }
                )

                # IMPORTANT: top-level fields required by tests
                alert["ip"] = last_attempt.get("ip")
                alert["fail_count"] = len(attempts)
                alert["last_attempt"] = last_attempt.get("timestamp")

                alerts.append(alert)

        return alerts