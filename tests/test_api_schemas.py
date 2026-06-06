import pytest
from jsonschema import validate, ValidationError
from api.schemas import security_event_schema, user_register_schema, format_checker

def test_user_register_schema_valid(api_client, app):
    data = {"username": "testuser", "password": "securepassword"}
    try:
        validate(instance=data, schema=user_register_schema, format_checker=format_checker)
    except ValidationError as e:
        pytest.fail(f"Valid data failed validation: {e.message}")

def test_user_register_schema_missing_username(api_client, app):
    data = {"password": "securepassword"}
    with pytest.raises(ValidationError):
        validate(instance=data, schema=user_register_schema, format_checker=format_checker)

def test_user_register_schema_short_password(api_client, app):
    data = {"username": "testuser", "password": "short"}
    with pytest.raises(ValidationError):
        validate(instance=data, schema=user_register_schema, format_checker=format_checker)

def test_security_event_schema_valid(api_client, app):
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

def test_security_event_schema_missing_required_field(api_client, app):
    data = {
        "timestamp": "2023-01-01T12:00:00Z",
        "event_type": "login_success"
    }
    with pytest.raises(ValidationError):
        validate(instance=data, schema=security_event_schema, format_checker=format_checker)

def test_security_event_schema_invalid_timestamp(api_client, app):
    data = {
        "timestamp": "invalid-date-time",
        "hostname": "server1",
        "event_type": "login_success",
        "message": "User logged in"
    }
    # Με το format_checker ενεργοποιημένο, το jsonschema θα εντοπίσει το λάθος format
    with pytest.raises(ValidationError) as excinfo:
        validate(instance=data, schema=security_event_schema, format_checker=format_checker)
    assert "is not a 'date-time'" in str(excinfo.value)

def test_security_event_schema_extra_field(api_client, app):
    data = {
        "timestamp": "2023-01-01T12:00:00Z",
        "hostname": "server1",
        "event_type": "login_success",
        "message": "User logged in",
        "extra_field": "some_value"
    }
    # Αν το schema σου έχει "additionalProperties": false, αυτό θα περάσει.
    # Αν το schema δεν το απαγορεύει, ίσως χρειαστεί να το αφαιρέσεις αν το τεστ αποτυγχάνει.
    with pytest.raises(ValidationError):
        validate(instance=data, schema=security_event_schema, format_checker=format_checker)