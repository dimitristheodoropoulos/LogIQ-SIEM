from typing import Dict

MITRE_MAPPING = {

    "Brute Force Attack": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "id": "T1110"
    },

    "anomalous_event_volume": {
        "tactic": "Discovery",
        "technique": "System Information Discovery",
        "id": "T1082"
    }
}


def enrich_alert(alert: dict) -> dict:
    alert_type = alert.get("alert_type")

    if alert_type in MITRE_MAPPING:
        alert.update({
            "mitre_tactic": MITRE_MAPPING[alert_type]["tactic"],
            "mitre_technique": MITRE_MAPPING[alert_type]["technique"],
            "mitre_id": MITRE_MAPPING[alert_type]["id"]
        })

    return alert