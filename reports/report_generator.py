import logging
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Union

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generates security reports based on a list of events.
    """
    def __init__(self, events: List[Dict]):
        self.events = events
        logger.info(f"ReportGenerator initialized with {len(events)} events.")

    def generate_summary(self, time_window: str) -> Dict:
        """
        Generates a summary report for events within a specified time window.
        
        :param time_window: A string representing the time window (e.g., '24h', '7d').
        :return: A dictionary containing the report summary.
        """
        end_time = datetime.utcnow()
        start_time = self._parse_time_window(time_window, end_time)

        if start_time is None:
            logger.error(f"Invalid time window format: {time_window}")
            return {"error": "Invalid time window format"}

        filtered_events = [
            event for event in self.events 
            if 'timestamp' in event and 
               isinstance(event['timestamp'], str) and # Ensure it's a string before parsing
               self._parse_timestamp(event['timestamp']) >= start_time
        ]

        # Convert timestamps to datetime objects for easier processing
        for event in filtered_events:
            event['timestamp_dt'] = self._parse_timestamp(event['timestamp'])

        total_events = len(filtered_events)
        event_type_counts = defaultdict(int)
        user_activity = defaultdict(int)
        ip_activity = defaultdict(int)
        
        for event in filtered_events:
            event_type_counts[event.get('event_type', 'unknown')] += 1
            if event.get('username'):
                user_activity[event['username']] += 1
            if event.get('ip'):
                ip_activity[event['ip']] += 1

        summary = {
            "report_generated_at": datetime.utcnow().isoformat(),
            "time_window": time_window,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "total_events": total_events,
            "event_type_counts": dict(event_type_counts),
            "top_users": sorted(user_activity.items(), key=lambda item: item[1], reverse=True)[:5],
            "top_ips": sorted(ip_activity.items(), key=lambda item: item[1], reverse=True)[:5]
        }
        logger.info("Report summary generated successfully.")
        return summary

    def _parse_time_window(self, time_window_str: str, current_time: datetime) -> Union[datetime, None]:
        """
        Parses a time window string (e.g., '24h', '7d') and returns the start datetime.
        """
        try: # Fix: Add try-except for ValueError
            value = int(time_window_str[:-1])
            unit = time_window_str[-1].lower()

            if unit == 'h':
                return current_time - timedelta(hours=value)
            elif unit == 'd':
                return current_time - timedelta(days=value)
            elif unit == 'm':
                return current_time - timedelta(minutes=value)
            else:
                return None
        except ValueError:
            logger.error(f"Failed to parse time window value: {time_window_str[:-1]}")
            return None


    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parses an ISO 8601 timestamp string into a datetime object.
        Handles 'Z' for UTC.
        """
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))

