import requests
import json
import os
import time
from datetime import datetime

# Ρυθμίσεις Σύνδεσης
MASTER_API_KEY = "LOGIQ_SUPER_SECRET_KEY_2026"
BASE_URL = "http://localhost:5000/api"

def get_data(endpoint, params=None):
    headers = {"X-API-KEY": MASTER_API_KEY}
    try:
        r = requests.get(f"{BASE_URL}/{endpoint}", headers=headers, params=params)
        if r.status_code == 200:
            return r.json()
        return {"error": f"Status {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def show_dashboard():
    while True:
        os.system('clear')
        print("="*60)
        print(f" 🛡️  LogIQ SIEM Terminal Monitor | {datetime.now().strftime('%H:%M:%S')}")
        print("="*60)

        # 1. Λήψη Events από το API
        raw_events = get_data("events/all")
        
        event_list = []
        if isinstance(raw_events, list):
            event_list = raw_events
        elif isinstance(raw_events, dict):
            event_list = raw_events.get('events') or raw_events.get('data') or []

        # 2. Smart Detection Logic (Εδώ γίνεται η "μαγεία" για το demo)
        # Επειδή το API alerts endpoint είναι άδειο, δημιουργούμε alerts 
        # σε πραγματικό χρόνο από τα ύποπτα events που βρίσκουμε στη βάση.
        smart_alerts = []
        for e in event_list:
            msg = str(e.get('message', '')).upper()
            etype = str(e.get('event_type', '')).lower()
            
            # Κριτήρια για να θεωρηθεί ένα event ως Alert
            if (e.get('severity') == 'critical' or 
                'SELECT' in msg or 
                'UNION' in msg or 
                'sql_injection' in etype or
                'unauthorized' in etype):
                
                smart_alerts.append({
                    "reason": e.get('message', 'Security Violation'),
                    "severity": e.get('severity', 'critical'),
                    "source_ip": e.get('source_ip') or e.get('ip') or 'N/A',
                    "type": e.get('event_type', 'Detection'),
                    "time": e.get('timestamp', 'Recent')
                })

        print(f"\n📊 Συνολικά Events στη Βάση: {len(event_list)}")
        print(f"🚨 Ενεργές Ειδοποιήσεις: {len(smart_alerts)}")
        print("-" * 60)

        # 3. Εμφάνιση των Alerts (τα τελευταία 8 για να χωράνε στην οθόνη)
        if smart_alerts:
            # Ταξινομούμε ώστε τα πιο πρόσφατα να είναι κάτω
            for a in smart_alerts[-8:]:
                color = "\033[91m" # Κόκκινο χρώμα
                reset = "\033[0m"
                print(f"{color}⚠️  ALERT: {a['reason']}{reset}")
                print(f"   Type: {a['type']} | IP: {a['source_ip']} | Sev: {a['severity']}")
                print(f"   Timestamp: {a['time']}")
                print("-" * 30)
        else:
            print("✅ Σύστημα Καθαρό. Δεν ανιχνεύθηκαν απειλές.")

        print("\n" + "="*60)
        print("Πιέστε CTRL+C για έξοδο...")
        time.sleep(3)

if __name__ == "__main__":
    show_dashboard()