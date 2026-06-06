#!/usr/bin/env python3
import requests
import json
import sqlite3
import time
from datetime import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Wazuh API configuration (use the actual IP or localhost)
WAZUH_API = "https://localhost:55000"   # ή https://192.168.x.x:55000
USER = "admin"
PASSWORD = "whStDCqDJRqslrZ8kwBrM*TxS2*U1n6C"

# LogIQ database path (SQLite)
DB_PATH = "logiq_siem.db"

def get_wazuh_token():
    auth = requests.post(f"{WAZUH_API}/security/user/authenticate", auth=(USER, PASSWORD), verify=False)
    auth.raise_for_status()
    return auth.json()["data"]["token"]

def fetch_alerts(token, minutes=5):
    headers = {"Authorization": f"Bearer {token}"}
    params = {"q": f"timestamp>now-{minutes}m", "sort": "-timestamp", "limit": 100}
    resp = requests.get(f"{WAZUH_API}/alerts", headers=headers, params=params, verify=False)
    resp.raise_for_status()
    return resp.json()["data"]["items"]

def insert_into_logiq(alert):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Ensure events table exists (simplified; adjust to your schema)
    c.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            hostname TEXT,
            event_type TEXT,
            message TEXT,
            ip TEXT,
            details TEXT
        )
    ''')
    c.execute('''
        INSERT INTO events (timestamp, hostname, event_type, message, ip, details)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        alert.get("timestamp"),
        alert.get("agent", {}).get("name", "unknown"),
        "wazuh_alert",
        alert.get("rule", {}).get("description", ""),
        alert.get("data", {}).get("srcip", ""),
        json.dumps(alert)
    ))
    conn.commit()
    conn.close()

def main():
    try:
        token = get_wazuh_token()
        print(f"[{datetime.now()}] Connected to Wazuh API")
        while True:
            alerts = fetch_alerts(token, minutes=5)
            for alert in alerts:
                insert_into_logiq(alert)
                print(f"[{datetime.now()}] Inserted alert: {alert.get('rule', {}).get('description')}")
            time.sleep(60)   # polling every minute
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
