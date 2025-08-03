from __future__ import annotations

import re
from datetime import datetime
import logging
import os
from typing import Union

logger = logging.getLogger(__name__)

def parse_auth_log(log_file_path: str) -> list[dict]:
    """
    Parses a Linux authentication log file (e.g., /var/log/auth.log)
    and extracts relevant security events.
    
    :param log_file_path: Path to the auth log file.
    :return: A list of dictionaries, each representing a parsed event.
    """
    events = []
    
    if not os.path.exists(log_file_path):
        logger.warning(f"Log file not found: {log_file_path}")
        return []

    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                event = _parse_log_line(line)
                if event:
                    events.append(event)
        logger.info(f"Successfully parsed {len(events)} events from {log_file_path}")
    except Exception as e:
        logger.error(f"Error reading or parsing log file {log_file_path}: {e}", exc_info=True)
    
    return events

def _parse_log_line(line: str) -> Union[dict, None]:
    """
    Parses a single line from the auth log and extracts event data.
    """
    ssh_accepted_password_re = re.compile(
        r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\w\d\.-]+)\s+sshd\[(\d+)\]:\s+Accepted password for\s+(\w+)\s+from\s+([\d\.]{7,15}|[a-fA-F0-9:]{2,})\s+port\s+(\d+)\s+ssh2"
    )
    ssh_failed_password_re = re.compile(
        r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\w\d\.-]+)\s+sshd\[(\d+)\]:\s+Failed password for\s+(?:invalid user\s+)?(\w+)\s+from\s+([\d\.]{7,15}|[a-fA-F0-9:]{2,})\s+port\s+(\d+)\s+ssh2"
    )
    ssh_invalid_user_re = re.compile(
        r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\w\d\.-]+)\s+sshd\[(\d+)\]:\s+Invalid user\s+(\w+)\s+from\s+([\d\.]{7,15}|[a-fA-F0-9:]{2,})\s+port\s+(\d+)"
    )
    ssh_accepted_publickey_re = re.compile(
        r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\w\d\.-]+)\s+sshd\[(\d+)\]:\s+Accepted publickey for\s+(\w+)\s+from\s+([\d\.]{7,15}|[a-fA-F0-9:]{2,})\s+port\s+(\d+)\s+ssh2:\s+(.+)"
    )
    sudo_command_re = re.compile(
        r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\w\d\.-]+)\s+sudo:\s+([\w\d\.-]+)\s+:\s+TTY=(.+?)\s+;\s+PWD=(.+?)\s+;\s+USER=(.+?)\s+;\s+COMMAND=(.+)"
    )

    current_year = datetime.now().year

    if match := ssh_accepted_password_re.search(line):
        timestamp_str, hostname, process_id, username, ip, port = match.groups()
        event_time = datetime.strptime(f"{timestamp_str} {current_year}", "%b %d %H:%M:%S %Y").isoformat()
        return {
            "timestamp": event_time,
            "hostname": hostname,
            "event_type": "ssh_accepted_password",
            "process": f"sshd[{process_id}]",
            "username": username,
            "ip": ip,
            "details": {"port": port, "message": line.strip()}
        }
    elif match := ssh_failed_password_re.search(line):
        timestamp_str, hostname, process_id, username, ip, port = match.groups()
        event_time = datetime.strptime(f"{timestamp_str} {current_year}", "%b %d %H:%M:%S %Y").isoformat()
        return {
            "timestamp": event_time,
            "hostname": hostname,
            "event_type": "ssh_failed_password",
            "process": f"sshd[{process_id}]",
            "username": username,
            "ip": ip,
            "details": {"port": port, "message": line.strip()}
        }
    elif match := ssh_invalid_user_re.search(line):
        timestamp_str, hostname, process_id, username, ip, port = match.groups()
        event_time = datetime.strptime(f"{timestamp_str} {current_year}", "%b %d %H:%M:%S %Y").isoformat()
        return {
            "timestamp": event_time,
            "hostname": hostname,
            "event_type": "ssh_invalid_user",
            "process": f"sshd[{process_id}]",
            "username": username,
            "ip": ip,
            "details": {"port": port, "message": line.strip()}
        }
    elif match := ssh_accepted_publickey_re.search(line):
        timestamp_str, hostname, process_id, username, ip, port, key_info = match.groups()
        event_time = datetime.strptime(f"{timestamp_str} {current_year}", "%b %d %H:%M:%S %Y").isoformat()
        return {
            "timestamp": event_time,
            "hostname": hostname,
            "event_type": "ssh_accepted_publickey",
            "process": f"sshd[{process_id}]",
            "username": username,
            "ip": ip,
            "details": {"port": port, "key_info": key_info, "message": line.strip()}
        }
    elif match := sudo_command_re.search(line):
        timestamp_str, hostname, username, tty, pwd, user_as, command = match.groups()
        event_time = datetime.strptime(f"{timestamp_str} {current_year}", "%b %d %H:%M:%S %Y").isoformat()
        return {
            "timestamp": event_time,
            "hostname": hostname,
            "event_type": "sudo_command",
            "process": "sudo",
            "username": username,
            "details": {"tty": tty, "pwd": pwd, "user_as": user_as, "command": command, "message": line.strip()}
        }
    
    return None
