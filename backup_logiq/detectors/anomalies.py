from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict


class AnomalyDetector:
    def __init__(self, db=None, config: Dict = None):
        self.db = db
        self.threshold_factor = (config or {}).get("ANOMALIES_THRESHOLD_FACTOR", 2)
        self.time_window = (config or {}).get("ANOMALIES_TIME_WINDOW", 60)
        self.min_baseline = (config or {}).get("ANOMALIES_MIN_EVENTS_FOR_BASELINE", 2)

    def _parse_time(self, ts):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except:
            return None

    def detect(self, events: List[Dict]) -> List[Dict]:
        if not events:
            return []

        now = datetime.now(timezone.utc)
        window_delta = timedelta(seconds=self.time_window)

        grouped = defaultdict(list)
        alerts = []

        # group by event type
        for e in events:
            etype = e.get("event_type", "unknown")
            grouped[etype].append(e)

        for etype, evs in grouped.items():

            timestamps = []
            for e in evs:
                t = self._parse_time(e.get("timestamp", ""))
                if t:
                    timestamps.append((t, e))

            if len(timestamps) < self.min_baseline:
                continue

            recent = [
                e for t, e in timestamps
                if now - t <= window_delta
            ]

            baseline = [
                e for t, e in timestamps
                if now - t > window_delta
            ]

            if not baseline:
                continue

            recent_count = len(recent)
            baseline_rate = len(baseline) / max(1, len(set(t for t, _ in timestamps)))

            threshold = baseline_rate * self.threshold_factor * len(timestamps)

            if recent_count > threshold:
                alerts.append({
                    "alert_type": "anomalous_event_volume",
                    "event_type": etype,
                    "recent_count": recent_count,
                    "baseline_mean": baseline_rate,
                    "message": f"Anomaly detected for {etype}"
                })

        return alerts