import requests
import time
import random
from datetime import datetime

API_URL = "http://localhost:5000/api/events" 
MASTER_API_KEY = "LOGIQ_SUPER_SECRET_KEY_2026"

def send_attack():
    users = ["admin", "root", "intruder_x", "db_service", "web_user", "guest"]
    ips = ["192.168.1.105", "45.33.22.11", "10.0.0.50", "185.22.33.1", "91.132.44.10"]
    
    # Προσθήκη ποικιλίας για ΧΡΩΜΑΤΑ στο dashboard
    attack_types = [
        {"type": "failed_login", "msg": "Failed password for user", "sev": "medium"},
        {"type": "sql_injection", "msg": "Detected SELECT * FROM users--", "sev": "critical"},
        {"type": "port_scan", "msg": "Multiple connection attempts on various ports", "sev": "high"},
        {"type": "unauthorized_access", "msg": "Access denied to /etc/shadow", "sev": "critical"}
    ]
    
    selected = random.choice(attack_types)
    
    payload = {
        "timestamp": datetime.now().isoformat(),
        "event_type": selected["type"],
        "username": random.choice(users),
        "ip": random.choice(ips),
        "hostname": "linux-server-01",
        "status": "failed",
        "severity": selected["sev"],
        "message": selected["msg"]
    }
    
    headers = {
        "X-API-KEY": MASTER_API_KEY,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(API_URL, json=payload, headers=headers)
        if response.status_code in [200, 201]:
            print(f"[✅] Sent {selected['type']} for {payload['username']} (Severity: {selected['sev']})")
        else:
            print(f"[❌] Error {response.status_code}: {response.text}")
    except Exception as e:
        print(f"[!] Connection Error: {e}")

if __name__ == "__main__":
    print("🔥 LogIQ SIEM - Colorful Attack Simulator")
    try:
        while True:
            send_attack()
            # Τυχαία καθυστέρηση για να φαίνεται φυσιολογικό
            time.sleep(random.uniform(0.3, 1.5))
    except KeyboardInterrupt:
        print("\n🛑 Stopped.")