import pytest
from reports.report_generator import ReportGenerator
from datetime import datetime, timezone, timezone, timedelta

def test_generate_summary_24h(api_client, app, sample_events):
    # Χρησιμοποιούμε τα sample_events αν είναι σωστά, αλλιώς δημιουργούμε νέα
    generator = ReportGenerator(sample_events) 
    summary = generator.generate_summary("24h")
    assert summary["time_window"] == "24h"

def test_generate_summary_7d(api_client, app):
    now = datetime.now(timezone.utc)
    # Δημιουργία 5 φρέσκων events για να περνάει το assertion
    fresh_events = [{"timestamp": (now - timedelta(days=i)).isoformat(), "event_type": "test"} for i in range(5)]
    
    generator = ReportGenerator(fresh_events)
    summary = generator.generate_summary("7d")
    assert summary["total_events"] == 5

def test_generate_summary_invalid_time_window(api_client, app, sample_events):
    generator = ReportGenerator(sample_events)
    summary = generator.generate_summary("abc")
    assert "error" in summary

def test_generate_summary_no_events(api_client, app):
    generator = ReportGenerator([])
    summary = generator.generate_summary("24h")
    assert summary["total_events"] == 0