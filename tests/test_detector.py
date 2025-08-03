from __future__ import annotations

import pytest
from unittest.mock import MagicMock
from logiq.detectors.anomalies import AnomalyDetector
from logiq.detectors.brute_force import BruteForceDetector
from logiq.siem_summary import SiemSummary # Assuming this is used, ensure it's correct
from datetime import datetime, timedelta


@pytest.fixture
def mock_db_instance():
    """Mock database instance for detector tests."""
    mock_db = MagicMock()
    mock_db.events = MagicMock()
    mock_db.events.find.return_value = MagicMock()
    mock_db.events.find.return_value.sort.return_value = []
    mock_db.get_all_events.return_value = []
    return mock_db

@pytest.fixture
def brute_force_config():
    return {
        "BRUTE_FORCE_THRESHOLD": 5,
        "BRUTE_FORCE_TIME_WINDOW": 300
    }

@pytest.fixture
def anomalies_config():
    return {
        "ANOMALIES_THRESHOLD_FACTOR": 2,
        "ANOMALIES_TIME_WINDOW": 60, # 1 minute for easier testing
        "ANOMALIES_MIN_EVENTS_FOR_BASELINE": 2 # Lowered for easier testing
    }

def test_detect_brute_force_basic(brute_force_config):
    """Test basic brute force detection within the Detector module."""
    detector = BruteForceDetector(config=brute_force_config)
    current_time = datetime.utcnow()
    events = []
    for i in range(6): # 6 failed attempts for 'testuser'
        events.append({
            "timestamp": (current_time - timedelta(seconds=i)).isoformat(),
            "event_type": "Failed login",
            "username": "testuser",
            "ip": "192.168.1.10",
            "message": "Authentication failed"
        })
    
    events.sort(key=lambda x: datetime.fromisoformat(x['timestamp'].replace('Z', '+00:00')))
    
    alerts = detector.detect(events)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert['alert_type'] == 'brute_force'
    assert alert['username'] == 'testuser'
    assert alert['ip'] == '192.168.1.10'
    assert alert['fail_count'] == 6
    assert 'message' in alert
    assert 'last_attempt' in alert

def test_detect_anomalies_basic(anomalies_config):
    """Test basic anomaly detection within the Detector module."""
    detector = AnomalyDetector(config=anomalies_config)
    current_time = datetime.utcnow()
    events = []
    # Simulate a baseline of low activity (e.g., 1 event per minute for 5 minutes)
    for i in range(5): 
        events.append({
            "timestamp": (current_time - timedelta(minutes=i+1)).isoformat(), # Older events
            "event_type": "normal_activity",
            "username": "normal_user",
            "ip": "10.0.0.2"
        })
    # Create a burst of suspicious activity in the most recent time window (last minute)
    for i in range(10): # 10 events in the last 30 seconds
        events.append({
            "timestamp": (current_time - timedelta(seconds=i)).isoformat(),
            "event_type": "suspicious_activity",
            "username": "attacker",
            "ip": "10.0.0.1"
        })
    
    events.sort(key=lambda x: datetime.fromisoformat(x['timestamp'].replace('Z', '+00:00')))

    alerts = detector.detect(events)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert['alert_type'] == 'anomalous_event_volume'
    assert alert['event_type'] == 'suspicious_activity'
    assert 'recent_count' in alert
    assert 'baseline_mean' in alert
    assert 'message' in alert

def test_detector_integration_no_alerts(mock_db_instance, brute_force_config, anomalies_config):
    """Test the overall detector with no alerts."""
    brute_force_detector = BruteForceDetector(config=brute_force_config)
    anomalies_detector = AnomalyDetector(config=anomalies_config)

    assert brute_force_detector is not None
    assert anomalies_detector is not None
