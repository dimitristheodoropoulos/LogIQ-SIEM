import pytest
from jsonschema import validate, ValidationError, FormatChecker # Ensure FormatChecker is imported
from logiq.api.schemas import security_event_schema, user_register_schema, format_checker # Assuming format_checker is exported

def test_user_register_schema_valid():
    """Test valid user registration data."""
    data = {"username": "testuser", "password": "securepassword"}
    try:
        validate(instance=data, schema=user_register_schema, format_checker=format_checker) # Pass format_checker
    except ValidationError as e:
        pytest.fail(f"Valid data failed validation: {e.message}")

def test_user_register_schema_missing_username():
    """Test user registration data missing username."""
    data = {"password": "securepassword"}
    with pytest.raises(ValidationError):
        validate(instance=data, schema=user_register_schema, format_checker=format_checker) # Pass format_checker

def test_user_register_schema_short_password():
    """Test user registration data with too short password."""
    data = {"username": "testuser", "password": "short"}
    with pytest.raises(ValidationError):
        validate(instance=data, schema=user_register_schema, format_checker=format_checker) # Pass format_checker

def test_security_event_schema_valid():
    """Test valid security event data."""
    data = {
        "timestamp": "2023-01-01T12:00:00Z",
        "hostname": "server1",
        "event_type": "login_success",
        "process": "sshd",
        "message": "User logged in",
        "ip": "192.168.1.1",
        "details": {"session_id": "abc123"}
    }
    try:
        validate(instance=data, schema=security_event_schema, format_checker=format_checker)
    except ValidationError as e:
        pytest.fail(f"Valid security event data failed validation: {e.message}")

def test_security_event_schema_missing_required_field():
    """Test security event data missing a required field."""
    data = {
        "timestamp": "2023-01-01T12:00:00Z",
        "event_type": "login_success"
    }
    with pytest.raises(ValidationError):
        validate(instance=data, schema=security_event_schema, format_checker=format_checker)

def test_security_event_schema_invalid_timestamp():
    """Test security event data with an invalid timestamp format."""
    data = {
        "timestamp": "invalid-date-time",
        "hostname": "server1",
        "event_type": "login_success",
        "message": "User logged in"
    }
    # This test should now pass because format_checker is correctly applied
    with pytest.raises(ValidationError):
        validate(instance=data, schema=security_event_schema, format_checker=format_checker)

def test_security_event_schema_extra_field():
    """Test security event data with an extra, unallowed field."""
    data = {
        "timestamp": "2023-01-01T12:00:00Z",
        "hostname": "server1",
        "event_type": "login_success",
        "message": "User logged in",
        "extra_field": "some_value"
    }
    # If "additionalProperties": False is in schema, this should raise ValidationError
    with pytest.raises(ValidationError): # Expect ValidationError due to additionalProperties: False
        validate(instance=data, schema=security_event_schema, format_checker=format_checker)
