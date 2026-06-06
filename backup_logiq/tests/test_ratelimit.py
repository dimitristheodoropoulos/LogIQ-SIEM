import pytest
from unittest.mock import patch, MagicMock
from flask import Flask, request
from flask_limiter import Limiter
# FIX: Import app fixture from conftest.py if not already in scope
# Assuming 'app' fixture is defined in conftest.py and available globally for tests.
# If you run tests from the root, conftest.py fixtures are automatically discovered.

# Define a mock get_ipaddr function since it's no longer in flask_limiter.util
def get_ipaddr() -> str: # Added return type hint for clarity
    """
    Returns the remote IP address or 'unknown' if not available.
    Ensures a string is always returned to satisfy Limiter's key_func type.
    """
    return request.remote_addr or 'unknown' # Fix: Ensures a string is always returned

# The test_app fixture is no longer needed here if it's provided by conftest.py
# If it's still defined here, it would override the conftest.py one for this file.
# Assuming you want to use the centralized 'app' fixture from conftest.py.
# @pytest.fixture
# def test_app():
#     app = Flask(__name__)
#     app.config.update({
#         "TESTING": True,
#         "RATELIMIT_STORAGE_URL": "memory://"
#     })
#     return app

def test_rate_limit_not_exceeded(app): # Use the 'app' fixture from conftest.py
    # Initialize Limiter with the 'app' instance from the fixture
    limiter = Limiter(app=app, key_func=get_ipaddr, default_limits=["1 per minute"])
    
    @app.route('/limited')
    @limiter.limit("1 per minute")
    def limited_route():
        return "OK"
    
    with app.test_client() as client: # Use app.test_client()
        response = client.get('/limited')
        assert response.status_code == 200

        
def test_rate_limit_exceeded(app): # Use the 'app' fixture from conftest.py
    """Test that a second request within the rate limit window is rejected."""
    # Initialize Limiter with the 'app' instance from the fixture
    limiter = Limiter(app=app, key_func=get_ipaddr, default_limits=["1 per minute"])
    
    @app.route('/limited_exceeded') # Use a unique route to avoid conflicts
    @limiter.limit("1 per minute")
    def limited_route_exceeded():
        return "OK"
    
    with app.test_client() as client: # Use app.test_client()
        # First request should succeed
        client.get('/limited_exceeded')
        # Second request should be rate-limited
        response = client.get('/limited_exceeded')
        assert response.status_code == 429
        
def test_unlimited_route_no_rate_limit(app): # Use the 'app' fixture from conftest.py
    """Test that a route without a rate limit is not affected."""
    # Initialize Limiter with the 'app' instance from the fixture
    limiter = Limiter(app=app, key_func=get_ipaddr) # No default_limits needed for this test
    
    @app.route('/unlimited')
    def unlimited_route():
        return "OK"
    
    with app.test_client() as client: # Use app.test_client()
        # Multiple requests should always succeed
        response1 = client.get('/unlimited')
        response2 = client.get('/unlimited')
        assert response1.status_code == 200
        assert response2.status_code == 200
