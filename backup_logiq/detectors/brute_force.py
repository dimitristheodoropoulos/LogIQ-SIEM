from collections import defaultdict
from typing import List, Dict
from siem_schema import create_alert


class BruteForceDetector:
    def __init__(self, db=None, config: Dict = None):
        self.db = db
        self.threshold = (config or {}).get("BRUTE_FORCE_THRESHOLD", 5)
        self.time_window = (config or {}).get("BRUTE_FORCE_TIME_WINDOW", 300)

    def detect(self, events: List[Dict]) -> List[Dict]:
        if not events:
            return []

        failed_by_user = defaultdict(list)
        alerts = []

        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            username = event.get("username")
            ip = event.get("ip")

            if "fail" in event_type and username and ip:
                failed_by_user[(username, ip)].append(event)

        for (username, ip), attempts in failed_by_user.items():

            if len(attempts) >= self.threshold:
                alerts.append(
                    create_alert(
                        alert_type="brute_force",
                        severity="high",
                        message=f"Brute force detected for user {username}",
                        event_type="authentication_failure",
                        username=username,
                        source="brute_force_detector",
                        details={
                            "fail_count": len(attempts)
                        }
                    ) | {   # <-- merge extra fields for tests
                        "ip": ip,
                        "fail_count": len(attempts)
                    }
                )

        return alerts