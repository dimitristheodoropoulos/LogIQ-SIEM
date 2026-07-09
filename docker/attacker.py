import requests
import time
from datetime import datetime, timezone  # ΔΙΟΡΘΩΣΗ: Προσθήκη του timezone για το UTC

# Το TOKEN σου παραμένει το ίδιο
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc3MjgyNjAxNCwianRpIjoiYmRkZWE0N2QtZDAxYS00Nzc1LWFlMjgtMGRmYzI0YTNiMjNkIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzcyODI2MDE0LCJjc3JmIjoiOTljNGJiNGItYzliYS00YTQ0LTgyZmQtM2E5MDg2ZDNlZGJkIiwiZXhwIjoxNzcyODI2OTE0fQ.lFX6KUEc3xNdwr-UEQWMEgZvuBrKhq2DIE7bK29i1X0" 
URL = "http://localhost:5000/api/events"

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

print(f"🚀 Ξεκινάει η αποστολή 5 live events στο {URL}...")

for i in range(1, 6):
    # Δημιουργία δεδομένων με δυναμικό timestamp (τρέχουσα ώρα UTC)
    current_time = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    data = [{
        "event_type": "failed_login",
        "username": f"intruder_{i}", # Διαφορετικό username για κάθε προσπάθεια
        "ip": f"10.0.0.{100 + i}",
        "hostname": "server-X",
        "message": f"Failed login attempt from python script (Attempt {i})",
        "timestamp": current_time
    }]

    try:
        response = requests.post(URL, json=data, headers=headers)
        if response.status_code in [200, 201]:
            print(f"✅ Sent event {i} | Time: {current_time} | Status: Success")
        else:
            print(f"❌ Sent event {i} | Status: Failed | Error: {response.text}")
    except Exception as e:
        print(f"⚠️ Error: {e}")
    
    time.sleep(1) # Αναμονή 1 δευτερολέπτου μεταξύ των αποστολών

print("\n🏁 Η διαδικασία ολοκληρώθηκε. Έλεγξε το Dashboard σου!")
