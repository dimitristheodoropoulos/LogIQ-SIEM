import pytest
from datetime import datetime, timedelta
from logiq.reports.report_generator import ReportGenerator # Corrected import to the class

@pytest.fixture
def sample_events():
    """Fixture to provide a list of sample events for testing."""
    now = datetime.utcnow()
    return [
        {"timestamp": (now - timedelta(minutes=5)).isoformat(), "event_type": "login_success", "username": "user1", "ip": "192.168.1.1"},
        {"timestamp": (now - timedelta(minutes=10)).isoformat(), "event_type": "login_failure", "username": "user2", "ip": "192.168.1.2"},
        {"timestamp": (now - timedelta(hours=1)).isoformat(), "event_type": "login_success", "username": "user1", "ip": "192.168.1.1"},
        {"timestamp": (now - timedelta(days=1)).isoformat(), "event_type": "logout", "username": "user3", "ip": "192.168.1.3"},
        {"timestamp": (now - timedelta(days=2)).isoformat(), "event_type": "login_failure", "username": "user2", "ip": "192.168.1.2"},
    ]

def test_generate_summary_24h(sample_events):
    """Test report generation for a 24-hour window."""
    generator = ReportGenerator(sample_events) # Instantiate the class
    summary = generator.generate_summary("24h")

    assert "report_generated_at" in summary
    assert summary["time_window"] == "24h"
    assert "start_time" in summary
    assert "end_time" in summary
    # Assuming all sample events fall within a 24h window for this test
    assert summary["total_events"] == 3 # Only events within the last 24h (login_success, login_failure, login_success)

    assert summary["event_type_counts"]["login_success"] == 2
    assert summary["event_type_counts"]["login_failure"] == 1
    assert "logout" not in summary["event_type_counts"]

    assert summary["top_users"][0][0] == "user1"
    assert summary["top_users"][0][1] == 2
    assert summary["top_users"][1][0] == "user2"
    assert summary["top_users"][1][1] == 1

def test_generate_summary_7d(sample_events):
    """Test report generation for a 7-day window."""
    generator = ReportGenerator(sample_events) # Instantiate the class
    summary = generator.generate_summary("7d")

    assert summary["time_window"] == "7d"
    assert summary["total_events"] == 5 # All events should be within 7 days

    assert summary["event_type_counts"]["login_success"] == 2
    assert summary["event_type_counts"]["login_failure"] == 2
    assert summary["event_type_counts"]["logout"] == 1

    assert len(summary["top_users"]) == 3 # user1, user2, user3

def test_generate_summary_invalid_time_window(sample_events):
    """Test report generation with an invalid time window."""
    generator = ReportGenerator(sample_events) # Instantiate the class
    summary = generator.generate_summary("abc")
    assert "error" in summary
    assert summary["error"] == "Invalid time window format"

def test_generate_summary_no_events():
    """Test report generation with no events."""
    generator = ReportGenerator([]) # Instantiate with empty list
    summary = generator.generate_summary("24h")
    assert summary["total_events"] == 0
    assert summary["event_type_counts"] == {}
    assert summary["top_users"] == []
    assert summary["top_ips"] == []
