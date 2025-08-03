from __future__ import annotations

import pytest
from unittest.mock import MagicMock
from logiq.detectors.anomalies import AnomalyDetector
from datetime import datetime, timedelta
import numpy as np


@pytest.fixture
def anomaly_detector():
    """Fixture to provide an AnomalyDetector instance with a mock config."""
    mock_config = {
        "ANOMALIES_THRESHOLD_FACTOR": 2,
        "ANOMALIES_TIME_WINDOW": 60, # 1 minute for easier testing
        "ANOMALIES_MIN_EVENTS_FOR_BASELINE": 2 # Lowered for easier testing
    }
    return AnomalyDetector(config=mock_config)

def test_detect_no_anomalies(anomaly_detector):
    """Test that no anomalies are detected with normal event rates."""
    current_time = datetime.utcnow()
    events = []
    # Create events that are consistent across multiple windows
    for i in range(10): # 10 events, 2 per minute for 5 minutes
        events.append({
            "timestamp": (current_time - timedelta(minutes=5 - (i // 2), seconds=(i % 2) * 20)).isoformat(),
            "event_type": "normal_login",
            "username": "user1",
            "ip": "192.168.1.1"
        })
    
    events.sort(key=lambda x: datetime.fromisoformat(x['timestamp'].replace('Z', '+00:00')))

    anomalies = anomaly_detector.detect(events)
    assert len(anomalies) == 0

def test_detect_with_anomaly(anomaly_detector):
    """Test that an anomaly is detected when event rate exceeds threshold."""
    current_time = datetime.utcnow()
    events = []
    
    # Simulate a baseline of low activity (e.g., 1 event per minute for 5 minutes)
    for i in range(5): 
        events.append({
            "timestamp": (current_time - timedelta(minutes=i+1)).isoformat(), # Older events
            "event_type": "normal_activity",
            "username": "user_normal",
            "ip": "192.168.1.2"
        })

    # Create a burst of suspicious activity in the most recent time window (last minute)
    # 10 events in the last 30 seconds, much higher than baseline
    for i in range(10): 
        events.append({
            "timestamp": (current_time - timedelta(seconds=i)).isoformat(),
            "event_type": "suspicious_activity",
            "username": "attacker",
            "ip": "10.0.0.1"
        })
    
    events.sort(key=lambda x: datetime.fromisoformat(x['timestamp'].replace('Z', '+00:00')))

    anomalies = anomaly_detector.detect(events)
    assert len(anomalies) == 1
    assert anomalies[0]['alert_type'] == 'anomalous_event_volume'
    assert anomalies[0]['event_type'] == 'suspicious_activity'
    assert anomalies[0]['recent_count'] == 10
    assert anomalies[0]['baseline_mean'] < 10


def test_detect_multiple_event_types(anomaly_detector):
    """Test anomaly detection across multiple event types."""
    current_time = datetime.utcnow()
    events = []

    # Normal events for type A (older, for baseline - 2 per min)
    for i in range(10):
        events.append({
            "timestamp": (current_time - timedelta(minutes=5 - (i // 2), seconds=(i % 2) * 10)).isoformat(),
            "event_type": "type_A_normal",
            "username": "userA",
            "ip": "1.1.1.1"
        })

    # Anomalous events for type B (recent, high count - 15 in last minute)
    for i in range(15):
        events.append({
            "timestamp": (current_time - timedelta(seconds=i)).isoformat(),
            "event_type": "type_B_anomaly",
            "username": "userB",
            "ip": "2.2.2.2"
        })
    
    # Normal events for type C (recent, low count - 1 in last minute)
    events.append({
        "timestamp": (current_time - timedelta(seconds=30)).isoformat(),
        "event_type": "type_C_normal",
        "username": "userC",
        "ip": "3.3.3.3"
    })
    
    events.sort(key=lambda x: datetime.fromisoformat(x['timestamp'].replace('Z', '+00:00')))

    anomalies = anomaly_detector.detect(events)
    assert len(anomalies) == 1
    assert anomalies[0]['event_type'] == 'type_B_anomaly'
    assert anomalies[0]['alert_type'] == 'anomalous_event_volume'
    assert anomalies[0]['recent_count'] == 15

def test_anomaly_detector_no_events_returns_empty_list(anomaly_detector):
    """Test that the detector returns an empty list if no events are provided."""
    anomalies = anomaly_detector.detect([])
    assert anomalies == []

def test_anomaly_detector_config_values_applied():
    """Test that the detector uses the configured threshold factor and time window."""
    custom_config = {
        "ANOMALIES_THRESHOLD_FACTOR": 5,
        "ANOMALIES_TIME_WINDOW": 120, # 2 minutes
        "ANOMALIES_MIN_EVENTS_FOR_BASELINE": 3
    }
    detector = AnomalyDetector(config=custom_config)
    assert detector.threshold_factor == 5
    assert detector.time_window == 120
