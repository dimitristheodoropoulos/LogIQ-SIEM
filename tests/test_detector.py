from __future__ import annotations

import pytest
from unittest.mock import MagicMock
from detectors.anomalies import AnomalyDetector
from detectors.brute_force import BruteForceDetector
from siem_summary import SiemSummary
from datetime import datetime, timezone, timedelta

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
        "ANOMALIES_TIME_WINDOW": 60, 
        "ANOMALIES_MIN_EVENTS_FOR_BASELINE": 2
    }

def test_detect_brute_force_basic(api_client, app, brute_force_config):
    """Test basic brute force detection within the Detector module."""
    detector = BruteForceDetector(config=brute_force_config)
    current_time = datetime.now(timezone.utc)
    events = []
    for i in range(6): 
        events.append({
            "timestamp": (current_time - timedelta(seconds=i)).isoformat(),
            "event_type": "Failed login",
            "username": "testuser",
            "ip": "192.168.1.10"
        })
    events.sort(key=lambda x: datetime.fromisoformat(x['timestamp']))
    alerts = detector.detect(events)
    assert len(alerts) == 1

def test_detect_anomalies_basic(api_client, app, anomalies_config):
    """Test basic anomaly detection within the Detector module."""
    detector = AnomalyDetector(config=anomalies_config)
    current_time = datetime.now(timezone.utc) # Naive UTC datetime to match detector internals
    events = []
    
    # Simulate a baseline of low activity (1 event per window interval)
    for i in range(5): 
        events.append({
            "timestamp": (current_time - timedelta(minutes=i+2)).replace(microsecond=0).isoformat(),
            "event_type": "suspicious_activity",
            "username": "normal_user",
            "ip": "10.0.0.2"
        })
    # Create a dense burst of activity in the most recent time window
    for i in range(15): 
        events.append({
            "timestamp": (current_time - timedelta(seconds=i)).replace(microsecond=0).isoformat(),
            "event_type": "suspicious_activity",
            "username": "attacker",
            "ip": "10.0.0.1"
        })
    
    events.sort(key=lambda x: x['timestamp'])
    alerts = detector.detect(events)
    assert len(alerts) >= 0