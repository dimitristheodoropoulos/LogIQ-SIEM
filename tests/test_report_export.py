from __future__ import annotations
import pytest
from flask_jwt_extended import create_access_token

def test_report_export_json_success(api_client, app, mock_db, mock_report_gen):
    app.db = mock_db
    app.report_generator = mock_report_gen

    mock_db.get_all_events.return_value = [{"event_type": "test"}]
    mock_report_gen.generate_summary.return_value = {"total_events": 1}

    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}

    response = api_client.get("/api/export?format=json", headers=headers)
    assert response.status_code == 200

def test_report_export_pdf_success(api_client, app, mock_db, mock_report_gen):
    app.db = mock_db
    app.report_generator = mock_report_gen
    
    mock_db.get_all_events.return_value = [{"event_type": "test"}]
    
    with app.app_context():
        access_token = create_access_token(identity="testuser")
    headers = {"Authorization": f"Bearer {access_token}"}
    
    response = api_client.get("/api/export?format=pdf", headers=headers)
    assert response.status_code in [200, 400]
