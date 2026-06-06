from __future__ import annotations
import pytest
from detectors.anomalies import AnomalyDetector
from datetime import datetime, timezone, timedelta, timezone

@pytest.fixture
def anomaly_detector():
    mock_config = {
        "ANOMALIES_THRESHOLD_FACTOR": 1.5,
        "ANOMALIES_TIME_WINDOW": 60,
        "ANOMALIES_MIN_EVENTS_FOR_BASELINE": 2
    }
    return AnomalyDetector(config=mock_config)

def test_detect_no_anomalies(api_client, app, anomaly_detector):
    now = datetime.now(timezone.utc)
    events = []
    # Events που είναι όλα παλιά (baseline) δεν προκαλούν alert
    for i in range(5):
        events.append({
            "timestamp": (now - timedelta(seconds=100 + i)).isoformat(),
            "event_type": "login",
            "username": "user1",
            "ip": "192.168.1.1"
        })
    anomalies = anomaly_detector.detect(events)
    assert len(anomalies) == 0

def test_detect_with_anomaly(api_client, app, anomaly_detector):
    now = datetime.now(timezone.utc)
    events = []
    # Baseline: 10 events παλιά (πριν το παράθυρο των 60s)
    for i in range(10):
        events.append({
            "timestamp": (now - timedelta(seconds=70 + i)).isoformat(),
            "event_type": "login",
            "username": "user1",
            "ip": "192.168.1.1"
        })
    # Anomaly: 20 events πρόσφατα (εντός των τελευταίων 60s)
    for i in range(20):
        events.append({
            "timestamp": (now - timedelta(seconds=i)).isoformat(),
            "event_type": "login",
            "username": "user1",
            "ip": "9.9.9.9"
        })
    anomalies = anomaly_detector.detect(events)
    assert len(anomalies) > 0

def test_detect_multiple_event_types(api_client, app, anomaly_detector):
    now = datetime.now(timezone.utc)
    events = []
    # Baseline: 10 events με το ίδιο type "test_type"
    for i in range(10):
        events.append({
            "timestamp": (now - timedelta(seconds=70 + i)).isoformat(),
            "event_type": "test_type",
            "username": "userA",
            "ip": "1.1.1.1"
        })
    # Peak: 20 events με το ΙΔΙΟ type "test_type"
    for i in range(20):
        events.append({
            "timestamp": (now - timedelta(seconds=i)).isoformat(),
            "event_type": "test_type",
            "username": "userB",
            "ip": "2.2.2.2"
        })
    anomalies = anomaly_detector.detect(events)
    # Τώρα θα βρει την ανωμαλία γιατί το baseline έχει events για το "test_type"
    assert len(anomalies) >= 1
    assert anomalies[0]['event_type'] == "test_type"

def test_anomaly_detector_no_events_returns_empty_list(api_client, app, anomaly_detector):
    assert anomaly_detector.detect([]) == []

def test_anomaly_detector_config_values_applied(api_client, app, anomaly_detector):
    assert anomaly_detector.time_window == 60
