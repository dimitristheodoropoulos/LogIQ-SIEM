import json
import os
from typing import Dict, Any

def load_mitre_mapping() -> Dict[str, Any]:
    """
    Φορτώνει το MITRE mapping από το αρχείο JSON.
    """
    # Διασφαλίζουμε ότι το path είναι σχετικό με τη θέση του script
    config_path = os.path.join(os.path.dirname(__file__), 'mitre_config.json')
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Σφάλμα φόρτωσης του mitre_config.json: {e}")
        return {}

# Φόρτωση κατά το initialization
MITRE_MAPPING = load_mitre_mapping()

def enrich_alert(alert: dict) -> dict:
    """
    Εμπλουτίζει ένα alert με το MITRE ATT&CK context διαβάζοντας από το config.
    """
    alert_type = alert.get("event_type")
    
    # Χρήση του δυναμικά φορτωμένου MITRE_MAPPING
    mitre_data = MITRE_MAPPING.get(alert_type, {
        "tactic": "N/A",
        "technique": "N/A",
        "id": "N/A"
    })

    # Ενσωμάτωση σε ξεχωριστό πεδίο
    alert["mitre_info"] = mitre_data
    
    return alert