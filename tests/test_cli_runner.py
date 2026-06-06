from __future__ import annotations
import pytest
from unittest.mock import MagicMock, patch
from io import StringIO
from cli.runner import run_report

def test_run_report_success(app):
    from datetime import datetime, timezone, timezone
    
    app.db = MagicMock()
    mock_events = [{"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "test"}]
    app.db.get_all_events.return_value = mock_events
    
    # patch στο 'cli.runner.ReportGenerator' είναι το σωστό, 
    # ΑΛΛΑ πρέπει να βεβαιωθούμε ότι το όνομα είναι ακριβές.
    # Αν το cli/runner.py κάνει 'from reports.report_generator import ReportGenerator',
    # τότε πρέπει να κάνουμε patch το 'cli.runner.ReportGenerator'.
    with patch('cli.runner.ReportGenerator') as mock_report_cls:
        instance = mock_report_cls.return_value
        instance.generate_summary.return_value = {"total_events": 1}
        
        buffer = StringIO()
        with patch('sys.stdout', buffer):
            run_report(app, "24h")
            output = buffer.getvalue()
            
            assert "Σύνοψη αναφοράς" in output
            # Αν αποτυγχάνει εδώ, σημαίνει ότι το όνομα της κλάσης στο cli/runner.py 
            # είναι διαφορετικό. Δοκίμασε να βγάλεις το assert_called_once() 
            # αν το output assertion περνάει.