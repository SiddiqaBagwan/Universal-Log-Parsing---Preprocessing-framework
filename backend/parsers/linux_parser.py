"""
LogNexus Linux Log Parser

Supports common Linux authentication/system log formats such as:

- SSH successful login
- SSH failed login
- SSH invalid user
- sudo activity
- systemd/service messages

The parser extracts structured fields while preserving
the original log message.
"""

import re
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

SSH_FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<src_ip>\S+) "
    r"port (?P<src_port>\d+)",
    re.IGNORECASE,
)

SSH_ACCEPTED_PASSWORD = re.compile(
    r"Accepted (?:password|publickey) for "
    r"(?P<user>\S+) from (?P<src_ip>\S+) "
    r"port (?P<src_port>\d+)",
    re.IGNORECASE,
)

SSH_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from "
    r"(?P<src_ip>\S+) port (?P<src_port>\d+)",
    re.IGNORECASE,
)

SUDO_COMMAND = re.compile(
    r"(?P<user>\S+)\s*:\s*.*COMMAND=(?P<command>.*)",
    re.IGNORECASE,
)

SUDO_SESSION = re.compile(
    r"(?P<user>\S+)\s*:\s*pam_unix\(sudo:session\): "
    r"session (?P<action>opened|closed)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

def parse_linux_timestamp(timestamp: str) -> str:
    """
    Convert common Linux syslog timestamps into ISO format.

    Example:
        Sep 17 05:30:42
        ->
        2026-09-17T05:30:42
    """

    current_year = datetime.now().year

    try:
        parsed = datetime.strptime(
            f"{current_year} {timestamp}",
            "%Y %b %d %H:%M:%S",
        )

        return parsed.isoformat()

    except ValueError:
        return timestamp


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_linux_log(log: str) -> dict[str, Any]:
    """
    Parse a Linux syslog/auth log.

    Returns a structured dictionary compatible with the
    LogNexus processing pipeline.
    """

    if not isinstance(log, str):
        raise TypeError("Linux log must be a string")

    log = log.strip()

    if not log:
        raise ValueError("Linux log is empty")

    result = {
        "protocol": "Linux",
        "source_type": "Linux",
        "timestamp": None,
        "hostname": None,
        "process": None,
        "pid": None,
        "message": log,
        "event_type": "Linux Event",
        "user": None,
        "source_ip": None,
        "source_port": None,
        "action": None,
        "outcome": None,
        "command": None,
    }

    # -----------------------------------------------------------------------
    # Parse standard Linux syslog header
    #
    # Example:
    # Sep 17 05:30:42 ubuntu-server sshd[2841]: Failed password...
    # -----------------------------------------------------------------------

    header_pattern = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+"
        r"\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>[A-Za-z0-9_.-]+)"
        r"(?:\[(?P<pid>\d+)\])?:\s*"
        r"(?P<message>.*)$"
    )

    match = header_pattern.match(log)

    if match:
        result["timestamp"] = parse_linux_timestamp(
            match.group("timestamp")
        )

        result["hostname"] = match.group("hostname")
        result["process"] = match.group("process")
        result["pid"] = match.group("pid")
        result["message"] = match.group("message")

    else:
        # Some Linux logs may not contain the standard syslog header.
        result["message"] = log

    message = result["message"]

    # -----------------------------------------------------------------------
    # SSH failed password
    # -----------------------------------------------------------------------

    match = SSH_FAILED_PASSWORD.search(message)

    if match:
        result["event_type"] = "SSH Login"
        result["action"] = "Login"
        result["outcome"] = "Failure"
        result["user"] = match.group("user")
        result["source_ip"] = match.group("src_ip")
        result["source_port"] = match.group("src_port")

        return result

    # -----------------------------------------------------------------------
    # SSH accepted login
    # -----------------------------------------------------------------------

    match = SSH_ACCEPTED_PASSWORD.search(message)

    if match:
        result["event_type"] = "SSH Login"
        result["action"] = "Login"
        result["outcome"] = "Success"
        result["user"] = match.group("user")
        result["source_ip"] = match.group("src_ip")
        result["source_port"] = match.group("src_port")

        return result

    # -----------------------------------------------------------------------
    # SSH invalid user
    # -----------------------------------------------------------------------

    match = SSH_INVALID_USER.search(message)

    if match:
        result["event_type"] = "SSH Login"
        result["action"] = "Invalid User Login"
        result["outcome"] = "Failure"
        result["user"] = match.group("user")
        result["source_ip"] = match.group("src_ip")
        result["source_port"] = match.group("src_port")

        return result

    # -----------------------------------------------------------------------
    # Sudo command
    # -----------------------------------------------------------------------

    if "COMMAND=" in message:

        match = SUDO_COMMAND.search(message)

        if match:
            result["event_type"] = "Privilege Escalation"
            result["action"] = "Sudo Command"
            result["outcome"] = "Success"
            result["user"] = match.group("user")
            result["command"] = match.group("command")

            return result

    # -----------------------------------------------------------------------
    # Sudo session
    # -----------------------------------------------------------------------

    match = SUDO_SESSION.search(message)

    if match:
        result["event_type"] = "Privilege Escalation"
        result["action"] = f"Sudo Session {match.group('action')}"
        result["outcome"] = "Success"
        result["user"] = match.group("user")

        return result

    # -----------------------------------------------------------------------
    # Generic system/service event
    # -----------------------------------------------------------------------

    if result["process"]:
        result["event_type"] = "Linux System Event"

    return result


# ---------------------------------------------------------------------------
# Local test
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    test_logs = [

        # SSH failure
        "Sep 17 05:30:42 ubuntu-server sshd[2841]: "
        "Failed password for admin from 10.99.160.55 port 52341 ssh2",

        # SSH success
        "Sep 17 05:31:10 ubuntu-server sshd[2850]: "
        "Accepted password for siddiqa from 10.99.160.20 port 49152 ssh2",

        # Invalid user
        "Sep 17 05:32:01 ubuntu-server sshd[2860]: "
        "Invalid user hacker from 10.99.160.99 port 44444",

        # Sudo
        "Sep 17 05:33:12 ubuntu-server sudo: "
        "siddiqa : TTY=pts/0 ; PWD=/home/siddiqa ; "
        "USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
    ]

    for log in test_logs:

        print("\n" + "=" * 70)
        print("RAW:")
        print(log)

        print("\nPARSED:")

        try:
            parsed = parse_linux_log(log)

            for key, value in parsed.items():
                print(f"{key}: {value}")

        except Exception as exc:
            print(f"ERROR: {exc}")