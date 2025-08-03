import pytest
import os
import tempfile
from logiq.parsers.auth_parser import parse_auth_log

@pytest.fixture
def temp_auth_log(tmp_path):
    """
    Creates a temporary auth.log file with sample data for testing.
    """
    log_content = """
Jan 1 12:00:00 hostname sshd[123]: Accepted password for user1 from 192.168.1.1 port 1234 ssh2
Jan 1 12:00:01 hostname sshd[124]: Failed password for user2 from 192.168.1.2 port 5678 ssh2
Jan 1 12:00:02 hostname sudo: user3 : TTY=pts/0 ; PWD=/home/user3 ; USER=root ; COMMAND=/bin/bash
Jan 1 12:00:03 hostname sshd[125]: Accepted publickey for user4 from 192.168.1.3 port 9012 ssh2: RSA SHA256:abc
Jan 1 12:00:04 hostname sshd[126]: Invalid user baduser from 192.168.1.4 port 3456
"""
    log_file = tmp_path / "test_auth.log"
    log_file.write_text(log_content)
    return str(log_file)

def test_parse_auth_log_success(temp_auth_log):
    """Test parsing a valid auth log file."""
    events = parse_auth_log(temp_auth_log)
    assert len(events) == 5
    assert events[0]['event_type'] == 'ssh_accepted_password'
    assert events[1]['event_type'] == 'ssh_failed_password'
    assert events[2]['event_type'] == 'sudo_command'
    assert events[3]['event_type'] == 'ssh_accepted_publickey'
    assert events[4]['event_type'] == 'ssh_invalid_user'
    assert events[0]['username'] == 'user1'
    assert events[1]['username'] == 'user2'
    assert events[2]['username'] == 'user3'
    assert events[3]['username'] == 'user4'
    assert events[4]['username'] == 'baduser'
    assert events[0]['ip'] == '192.168.1.1'
    assert events[1]['ip'] == '192.168.1.2'
    assert events[4]['ip'] == '192.168.1.4'

def test_parse_auth_log_file_not_found():
    """Test parsing a non-existent log file."""
    events = parse_auth_log("non_existent_log.log")
    assert events == []

def test_parse_auth_log_empty_file(tmp_path):
    """Test parsing an empty log file."""
    empty_log_file = tmp_path / "empty_auth.log"
    empty_log_file.write_text("")
    events = parse_auth_log(str(empty_log_file))
    assert events == []
