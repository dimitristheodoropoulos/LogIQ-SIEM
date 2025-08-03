from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta
import numpy as np
from typing import List, Dict, Union

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Detects anomalies in security events based on statistical analysis.
    """
    def __init__(self, config: Dict):
        self.config = config
        self.threshold_factor = config.get('ANOMALIES_THRESHOLD_FACTOR', 3)
        self.time_window = config.get('ANOMALIES_TIME_WINDOW', 3600)  # in seconds
        self.min_events_for_baseline = config.get('ANOMALIES_MIN_EVENTS_FOR_BASELINE', 10)
        logging.info(f"AnomalyDetector initialized with threshold factor: {self.threshold_factor}, time window: {self.time_window}s, and min events for baseline: {self.min_events_for_baseline}")

    def detect(self, events: List[Dict]) -> List[Dict]:
        """
        Detects anomalies based on a sudden high volume of events for a specific event_type.
        Anomalies are detected if the event count in the last time window exceeds
        a baseline by a certain threshold.
        """
        logging.info(f"Starting anomalies detection on {len(events)} events.")
        
        event_counts_by_type = defaultdict(list)
        now = datetime.utcnow()
        alerts = []
        
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
            if event_type:
                event_counts_by_type[event_type].append(event)
        
        for event_type, events_list in event_counts_by_type.items():
            events_list.sort(key=lambda x: x['timestamp_dt'])

            # Define the current window (last `self.time_window` seconds)
            current_window_start = now - timedelta(seconds=self.time_window)
            recent_events = [e for e in events_list if e['timestamp_dt'] >= current_window_start]
            recent_count = len(recent_events)

            # Define historical windows for baseline calculation
            # We'll use multiple non-overlapping windows preceding the current one
            historical_counts = []
            for i in range(1, 6): # Look at 5 historical windows
                hist_window_end = now - timedelta(seconds=self.time_window * i)
                hist_window_start = hist_window_end - timedelta(seconds=self.time_window)
                
                count_in_hist_window = sum(1 for e in events_list if hist_window_start <= e['timestamp_dt'] < hist_window_end)
                historical_counts.append(count_in_hist_window)
            
            # Filter out zero counts if they are not representative (e.g., if there's genuinely no activity)
            # Or, ensure we have enough non-zero data points for a meaningful baseline
            meaningful_historical_counts = [c for c in historical_counts if c > 0]
            
            if len(meaningful_historical_counts) < self.min_events_for_baseline:
                logging.info(f"Skipping anomalies check for '{event_type}' due to insufficient meaningful historical data ({len(meaningful_historical_counts)} data points).")
                # If there's a sudden burst and no established baseline, it could still be an anomaly
                if recent_count > self.threshold_factor * 2: # Arbitrary high threshold for no baseline
                     alert_data = {
                        "alert_type": "anomalous_event_volume",
                        "event_type": event_type,
                        "recent_count": recent_count,
                        "baseline_mean": 0.0,
                        "baseline_std": 0.0,
                        "timestamp": now.isoformat(),
                        "message": (
                            f"Anomalous event volume detected for '{event_type}'. "
                            f"Recent count ({recent_count}) is significantly high with no established baseline."
                        )
                    }
                     if recent_count > 0: # Only add if there's actually a recent count
                        alerts.append(alert_data)
                        logging.warning(f"Anomaly alert generated: {alert_data}")
                continue

            baseline_mean = np.mean(meaningful_historical_counts)
            baseline_std = np.std(meaningful_historical_counts)

            # Detect anomaly: If recent count is significantly higher than baseline
            # Using mean + threshold_factor * std_dev for detection
            if recent_count > (baseline_mean + self.threshold_factor * baseline_std):
                alert_data = {
                    "alert_type": "anomalous_event_volume",
                    "event_type": event_type,
                    "recent_count": recent_count,
                    "baseline_mean": round(baseline_mean, 2),
                    "baseline_std": round(baseline_std, 2),
                    "timestamp": now.isoformat(),
                    "message": (
                        f"Anomalous event volume detected for '{event_type}'. "
                        f"Recent count ({recent_count}) is significantly higher than the baseline mean ({round(baseline_mean, 2)})."
                    )
                }
                alerts.append(alert_data)
                logging.warning(f"Anomaly alert generated: {alert_data}")
        
        logging.info(f"Anomalies detection finished. Found {len(alerts)} alerts.")
        return alerts
