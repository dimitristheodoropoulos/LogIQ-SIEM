from __future__ import annotations
import re
from datetime import datetime
import logging
import os
from typing import Union

logger = logging.getLogger(__name__)

def parse_auth_log(log_file_path: str) -> list[dict]:
    events = []
    if not os.path.exists(log_file_path):
        return []
    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                event = _parse_log_line(line)
                if event:
                    events.append(event)
    except Exception as e:
        logger.error(f"Error parsing log: {e}")
    return events

def _parse_log_line(line: str) -> Union[dict, None]:
    # Regex που υποστηρίζει και ISO (Xubuntu) και κλασικό Syslog format
    timestamp_re = r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\d.+-:]+|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})'
    hostname_re = r'\s+(?P<hostname>[\w\d\.-]+)'
    
    ssh_failed_re = re.compile(timestamp_re + hostname_re + r'\s+sshd\[(?P<pid>\d+)\]:\s+Failed password for\s+(?:invalid user\s+)?(?P<user>\w+)\s+from\s+(?P<ip>[\d\.:a-fA-F]+)')
    sudo_re = re.compile(timestamp_re + hostname_re + r'\s+sudo:\s+(?P<user>[\w\d\.-]+)\s+:\s+TTY=(?P<tty>.+?)\s+;\s+PWD=(?P<pwd>.+?)\s+;\s+USER=(?P<user_as>.+?)\s+;\s+COMMAND=(?P<cmd>.+)')

    def format_ts(ts_str):
        try:
            if 'T' in ts_str: # ISO Format
                return datetime.fromisoformat(ts_str.replace('Z', '+00:00')).isoformat()
            # Old Syslog Format
            return datetime.strptime(f"{ts_str} {datetime.now().year}", "%b %d %H:%M:%S %Y").isoformat()
        except:
            return datetime.now().isoformat()

    # Έλεγχος για SSH Failure
    if match := ssh_failed_re.search(line):
        d = match.groupdict()
        return {
            "timestamp": format_ts(d['timestamp']),
            "hostname": d['hostname'],
            "event_type": "ssh_failed_password",
            "process": f"sshd[{d['pid']}]",
            "username": d['user'],
            "ip": d['ip'],
            "details": {"message": line.strip()}
        }
    
    # Έλεγχος για Sudo Command
    if match := sudo_re.search(line):
        d = match.groupdict()
        return {
            "timestamp": format_ts(d['timestamp']),
            "hostname": d['hostname'],
            "event_type": "sudo_command",
            "process": "sudo",
            "username": d['user'],
            "details": {"command": d['cmd'], "user_as": d['user_as'], "message": line.strip()}
        }
    
    return None