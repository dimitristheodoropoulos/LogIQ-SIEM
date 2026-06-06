from __future__ import annotations
import pytest
from parsers.auth_parser import parse_auth_log

@pytest.fixture
def temp_auth_log(tmp_path):
    log_content = """
Jan 1 12:00:00 hostname sshd[123]: Failed password for user1 from 192.168.1.1 port 1234 ssh2
Jan 1 12:00:02 hostname sudo: user3 : TTY=pts/0 ; PWD=/home/user3 ; USER=root ; COMMAND=/bin/bash
"""
    log_file = tmp_path / "test_auth.log"
    log_file.write_text(log_content)
    return str(log_file)

def test_parse_auth_log_success(api_client, app, temp_auth_log):
    events = parse_auth_log(temp_auth_log)
    assert len(events) == 2
    assert events[0]['event_type'] == 'ssh_failed_password'
    assert events[1]['event_type'] == 'sudo_command'

def test_parse_auth_log_file_not_found(api_client, app):
    events = parse_auth_log("non_existent_log.log")
    assert events == []

def test_parse_auth_log_empty_file(api_client, app, tmp_path):
    empty_log_file = tmp_path / "empty_auth.log"
    empty_log_file.write_text("")
    events = parse_auth_log(str(empty_log_file))
    assert events == []