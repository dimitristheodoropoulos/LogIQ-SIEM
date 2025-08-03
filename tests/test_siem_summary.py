import logging
from datetime import datetime, timedelta
from collections import defaultdict

# Assuming db_mongo is the primary database interaction module
# from db.db_mongo import connect_db, insert_events, get_events, get_alerts, get_users

def generate_siem_summary(db, start_date=None, end_date=None):
    """
    Generates a summary of SIEM data, including event counts, alert statistics,
    and recent activity.
    
    Args:
        db: The database connection object (e.g., MongoDB client).
        start_date (datetime, optional): The start date for the summary period.
                                         Defaults to 24 hours ago.
        end_date (datetime, optional): The end date for the summary period.
                                       Defaults to now.
    Returns:
        dict: A dictionary containing the SIEM summary.
    """
    logging.info("Generating SIEM summary...")

    now = datetime.utcnow()
    if end_date is None:
        end_date = now
    if start_date is None:
        start_date = now - timedelta(hours=24) # Default to last 24 hours

    summary = {
        "total_events": 0,
        "events_by_type": defaultdict(int),
        "total_alerts": 0,
        "brute_force_alerts_detected": 0,
        "anomaly_alerts_detected": 0,
        "most_common_ips": {},
        "recent_events": [],
        "recent_alerts": []
    }

    # Fetch events within the time range
    # Assuming db.events.find() supports date range queries
    events_filter = {"timestamp": {"$gte": start_date.isoformat(), "$lte": end_date.isoformat()}}
    
    # Ensure to handle potential errors if db or db.events is None
    if db and hasattr(db, 'events') and hasattr(db.events, 'find'):
        events_cursor = db.events.find(events_filter).sort("timestamp", -1)
        all_events = list(events_cursor) # Convert cursor to list
        summary["total_events"] = len(all_events)

        ip_counts = defaultdict(int)
        for event in all_events:
            event_type = event.get("event_type")
            if event_type:
                summary["events_by_type"][event_type] += 1
            ip = event.get("ip")
            if ip:
                ip_counts[ip] += 1
        
        # Sort IPs by count and get top N (e.g., top 5)
        summary["most_common_ips"] = dict(sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)[:5])
        
        # Get recent events (e.g., last 10)
        summary["recent_events"] = all_events[:10]
    else:
        logging.warning("Database or events collection not available for summary generation.")


    # Fetch alerts within the time range
    # Assuming db.alerts.find() supports date range queries and filtering by alert_type
    alerts_filter = {"timestamp": {"$gte": start_date.isoformat(), "$lte": end_date.isoformat()}}

    if db and hasattr(db, 'alerts') and hasattr(db.alerts, 'find'):
        alerts_cursor = db.alerts.find(alerts_filter).sort("timestamp", -1)
        all_alerts = list(alerts_cursor) # Convert cursor to list
        summary["total_alerts"] = len(all_alerts)

        for alert in all_alerts:
            alert_type = alert.get("alert_type")
            if alert_type == "brute_force":
                summary["brute_force_alerts_detected"] += 1
            elif alert_type == "anomalous_event_volume": # Use the correct alert type
                summary["anomaly_alerts_detected"] += 1
        
        # Get recent alerts (e.g., last 5)
        summary["recent_alerts"] = all_alerts[:5]
    else:
        logging.warning("Database or alerts collection not available for summary generation.")

    logging.info("SIEM summary generated successfully.")
    return summary

