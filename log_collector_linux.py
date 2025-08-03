from __future__ import annotations

import argparse
import logging
import requests
import json
import os
import sys
from typing import Union

from logiq.parsers.auth_parser import parse_auth_log 
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def get_auth_token(base_url: str, username: str, password: str) -> Union[str, None]:
    """
    Πραγματοποιεί σύνδεση και επιστρέφει ένα JWT token.
    """
    login_url = f"{base_url}/api/login"
    login_data = {"username": username, "password": password}
    try:
        response = requests.post(login_url, json=login_data, timeout=10)
        if response.status_code == 200:
            token = response.json().get("access_token")
            if token:
                logger.info("Επιτυχής λήψη JWT token")
                return token
            else:
                logger.error(f"Αποτυχία σύνδεσης")
        else:
            logger.error(f"Αποτυχία σύνδεσης: Κωδικός {response.status_code}, Μήνυμα: {response.text}")
            logger.error(f"Αποτυχία σύνδεσης")
    except requests.exceptions.RequestException as e:
        logger.error(f"Σφάλμα κατά τη σύνδεση με το API: {e}")
    return None

def read_auth_log(path: str, last_n: Union[int, None] = None) -> list[dict]:
    """
    Διαβάζει το auth.log, χρησιμοποιεί τον parser και επιστρέφει parsed γεγονότα.
    """
    events = parse_auth_log(path)
    
    if last_n:
        return events[-last_n:]
    return events

def send_events(api_url: str, events: list[dict], token: str) -> bool:
    """
    Στέλνει τα συμβάντα στο API χρησιμοποιώντας JWT token.
    """
    if not token:
        logger.error("Δεν υπάρχει JWT token. Παραλείπεται η αποστολή συμβάντων.")
        return False
    if not events:
        logger.info("Δεν υπάρχουν συμβάντα για αποστολή")
        return False
        
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    
    try:
        resp = requests.post(api_url, json=events, headers=headers, timeout=10)
        if resp.status_code == 201:
            logger.info(f"Επιτυχής αποστολή {len(events)} συμβάντων στο API")
            return True
        else:
            logger.error(f"Αποτυχία αποστολής συμβάντων. Κωδικός: {resp.status_code}, Μήνυμα: {resp.text}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Εξαίρεση κατά την αποστολή συμβάντων στο API: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Linux auth log collector for logiq.")
    parser.add_argument("--logfile", default="/var/log/auth.log", help="Path to auth log file")
    parser.add_argument("--last", type=int, help="Only read last N lines")
    parser.add_argument("--send", action="store_true", help="Send events to Flask API")
    parser.add_argument("--api-url", default="http://127.0.0.1:5000", help="Base URL of the Flask API")
    parser.add_argument("--username", help="Username for API authentication")
    parser.add_argument("--password", help="Password for API authentication")
    args = parser.parse_args()

    if args.send and (not args.username or not args.password):
        parser.error("Η επιλογή --send απαιτεί όνομα χρήστη (--username) και κωδικό (--password).")

    logger.info(f"▶️  Ανάγνωση αρχείου καταγραφής: {args.logfile} (τελευταίες {args.last if args.last else 'όλες'} γραμμές)")
    events = read_auth_log(args.logfile, args.last)
    logger.info(f"✅ Αναλύθηκαν {len(events)} συμβάντα.")

    jwt_token = None
    if args.send:
        jwt_token = get_auth_token(args.api_url, args.username, args.password)
        if jwt_token is None: # FIX: Explicitly check for None
            logger.error("❌ Αδυναμία αυθεντικοποίησης. Η εφαρμογή θα τερματιστεί.")
            sys.exit(1)

    if events:
        export_path = os.path.join(os.getcwd(), "linux_auth_events.json")
        try:
            with open(export_path, "w", encoding="utf-8") as f:
                json.dump(events, f, ensure_ascii=False, indent=2)
            logger.info(f"✅ Εξαγωγή συμβάντων σε {export_path}")
        except Exception as e:
            logger.error(f"Σφάλμα κατά την εξαγωγή τοπικού αρχείου JSON: {e}")


    if args.send and events and jwt_token:
        api_events_url = f"{args.api_url}/api/events"
        logger.info(f"▶️  Αποστολή συμβάντων στο API: {api_events_url}")
        send_events(api_events_url, events, jwt_token)

if __name__ == "__main__":
    main()
