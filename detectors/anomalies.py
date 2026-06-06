from collections import defaultdict
from typing import List, Dict
from datetime import datetime, timedelta, timezone
from siem_schema import create_alert

class AnomalyDetector:
    def __init__(self, db=None, config: Dict = None):
        self.db = db or {}
        config = config or {}
        self.threshold_factor = config.get("ANOMALIES_THRESHOLD_FACTOR", 2)
        self.time_window = config.get("ANOMALIES_TIME_WINDOW", 60)
        self.min_events = config.get("ANOMALIES_MIN_EVENTS_FOR_BASELINE", 2)

    def _parse_time(self, ts: str) -> datetime:
        """Μετατροπή string σε UTC-aware datetime με ασφάλεια."""
        try:
            if not ts:
                return datetime.now(timezone.utc)
            # Μετατροπή σε UTC-aware datetime
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError, AttributeError):
            return datetime.now(timezone.utc)

    def detect(self, events: List[Dict]) -> List[Dict]:
        if not events:
            return []

        now = datetime.now(timezone.utc)
        grouped = defaultdict(list)
        for e in events:
            # Ομαδοποίηση με βάση το event_type
            event_type = e.get("event_type", "unknown")
            grouped[event_type].append(e)

        alerts = []
        recent_cutoff = now - timedelta(seconds=self.time_window)

        for event_type, items in grouped.items():
            parsed = []
            for e in items:
                ts = self._parse_time(e.get("timestamp", ""))
                parsed.append((ts, e))

            # Ταξινόμηση με βάση το timestamp
            parsed.sort(key=lambda x: x[0])

            recent = [e for t, e in parsed if t >= recent_cutoff]
            baseline = [e for t, e in parsed if t < recent_cutoff]

            # Αν δεν έχουμε αρκετά events για baseline, αγνοούμε την ανωμαλία
            if len(baseline) < self.min_events:
                continue

            # Υπολογισμός ρυθμού (events ανά λεπτό)
            window_minutes = self.time_window / 60
            baseline_rate = len(baseline) / max(1, window_minutes)
            recent_count = len(recent)

            # Ανίχνευση ανωμαλίας
            if recent_count >= self.threshold_factor * max(1, baseline_rate):
                alerts.append(create_alert(
                    alert_type="anomalous_event_volume",
                    severity="medium",
                    message=f"Anomaly detected for {event_type}: {recent_count} events in window",
                    event_type=event_type,
                    source="anomaly_detector",
                    details={
                        "recent_count": recent_count, 
                        "baseline_mean": round(baseline_rate, 2),
                        "time_window_seconds": self.time_window
                    }
                ))
        return alerts