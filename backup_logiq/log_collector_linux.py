from __future__ import annotations
import argparse
import logging
import requests
import json
import os
import sys
from typing import Union
from parsers.auth_parser import parse_auth_log 

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def get_auth_token(base_url: str, username: str, password: str) -> Union[str, None]:
    """
    Δοκιμάζει πολλαπλά endpoints για login (με ή χωρίς /api) για αποφυγή 404.
    """
    base_url = base_url.rstrip('/')
    urls_to_try = [f"{base_url}/api/login", f"{base_url}/login"]
    
    for login_url in urls_to_try:
        try:
            logger.info(f"Προσπάθεια αυθεντικοποίησης στο: {login_url}")
            response = requests.post(login_url, json={"username": username, "password": password}, timeout=5)
            if response.status_code == 200:
                token = response.json().get("access_token")
                if token:
                    logger.info("✅ Επιτυχής λήψη JWT token")
                    return token
        except Exception as e:
            continue
    return None

def read_auth_log(path: str, last_n: Union[int, None] = None) -> list[dict]:
    events = parse_auth_log(path)
    if last_n:
        return events[-last_n:]
    return events

def send_events(api_url: str, events: list[dict], token: str) -> bool:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    try:
        resp = requests.post(api_url, json=events, headers=headers, timeout=10)
        if resp.status_code in [200, 201]:
            logger.info(f"🚀 Επιτυχής αποστολή {len(events)} συμβάντων στο API")
            return True
        else:
            logger.error(f"❌ Αποτυχία αποστολής. Κωδικός: {resp.status_code}")
            return False
    except Exception as e:
        logger.error(f"❌ Σφάλμα κατά την αποστολή: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Linux auth log collector for LogIQ-SIEM.")
    parser.add_argument("--logfile", default="/var/log/auth.log", help="Path to auth log file")
    parser.add_argument("--last", type=int, help="Only read last N lines")
    parser.add_argument("--send", action="store_true", help="Send events to API")
    parser.add_argument("--api-url", default="http://127.0.0.1:5000", help="Base URL of API")
    parser.add_argument("--username", help="API Username")
    parser.add_argument("--password", help="API Password")
    args = parser.parse_args()

    if args.send and (not args.username or not args.password):
        parser.error("Η επιλογή --send απαιτεί --username και --password.")

    logger.info(f"🔍 Ανάγνωση: {args.logfile}")
    events = read_auth_log(args.logfile, args.last)
    logger.info(f"📊 Βρέθηκαν {len(events)} συμβάντα.")

    if args.send:
        jwt_token = get_auth_token(args.api_url, args.username, args.password)
        if not jwt_token:
            logger.error("❌ Αδυναμία σύνδεσης (404 ή λάθος credentials).")
            sys.exit(1)
        
        if events:
            # Δυναμική κατασκευή του σωστού endpoint για τα events
            clean_url = args.api_url.rstrip('/')
            if "/api" in clean_url:
                api_events_url = f"{clean_url}/events"
            else:
                api_events_url = f"{clean_url}/api/events"
            
            send_events(api_events_url, events, jwt_token)
        else:
            logger.info("Σημείωση: Δεν υπάρχουν νέα συμβάντα για αποστολή.")

if __name__ == "__main__":
    main()