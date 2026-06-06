from __future__ import annotations

import pytest
from unittest.mock import MagicMock
from detectors.brute_force import BruteForceDetector
from datetime import datetime, timezone, timedelta

@pytest.fixture
def brute_force_config():
    return {
        "BRUTE_FORCE_THRESHOLD": 5,
        "BRUTE_FORCE_TIME_WINDOW": 300 # 5 minutes
    }

def test_detect_brute_force_basic(api_client, app, brute_force_config):
    """Test basic brute force detection for a single user/IP."""
    detector = BruteForceDetector(config=brute_force_config)
    current_time = datetime.now(timezone.utc)
    events = []
    # 6 failed attempts within a short time window (should trigger)
    for i in range(6):
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

def test_detect_brute_force_multiple_users_one_ip(api_client, app, brute_force_config):
    """Test detection for multiple users from the same IP, should be separate alerts."""
    detector = BruteForceDetector(config=brute_force_config)
    current_time = datetime.now(timezone.utc)
    events = []

    # User1: 6 failed attempts from an IP
    for i in range(6):
        events.append({
            "timestamp": (current_time - timedelta(seconds=i)).isoformat(),
            "event_type": "Failed login",
            "username": "user1",
            "ip": "192.168.1.10",
            "message": "Authentication failed"
        })
    # User2: 6 failed attempts from the same IP
    for i in range(6):
        events.append({
            "timestamp": (current_time - timedelta(seconds=i)).isoformat(),
            "event_type": "Failed login",
            "username": "user2",
            "ip": "192.168.1.10",
            "message": "Authentication failed"
        })
    
    events.sort(key=lambda x: datetime.fromisoformat(x['timestamp'].replace('Z', '+00:00')))
    
    alerts = detector.detect(events)
    assert len(alerts) == 2
    assert any(a['username'] == 'user1' for a in alerts)
    assert any(a['username'] == 'user2' for a in alerts)

def test_detect_brute_force_missing_fields(api_client, app, brute_force_config):
    """Test handling of events with missing username or IP."""
    detector = BruteForceDetector(config=brute_force_config)
    current_time = datetime.now(timezone.utc)
    events = [
        {"timestamp": current_time.isoformat(), "event_type": "Failed login", "ip": "1.1.1.1", "message": "Failed login"},
        {"timestamp": current_time.isoformat(), "event_type": "Failed login", "username": "user", "message": "Failed login"},
    ]
    alerts = detector.detect(events)
    assert len(alerts) == 0