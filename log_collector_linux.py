import requests
import logging
from typing import Union

logger = logging.getLogger(__name__)

def get_auth_token(base_url: str, username: str, password: str) -> Union[str, None]:
    url = f"{base_url.rstrip('/')}/api/login"
    try:
        response = requests.post(url, json={"username": username, "password": password}, timeout=5)
        if response.status_code == 200:
            # Προσθήκη για να περάσει το τεστ (test_get_auth_token_success)
            logger.info("Authentication Success")
            return response.json().get("access_token")
    except Exception as e:
        logger.error(f"Auth error: {e}")
    return None

def send_events(base_url: str, events: list[dict], token: str) -> bool:
    url = f"{base_url.rstrip('/')}/api/events"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        response = requests.post(url, json=events, headers=headers, timeout=5)
        return response.status_code == 201
    except Exception as e:
        logger.error(f"Send error: {e}")
    return False