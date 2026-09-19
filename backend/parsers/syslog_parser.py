"""
LogNexus Syslog Parser

Supports:
    - RFC 5424 Syslog
    - Common legacy/BSD-style Syslog

The parser extracts protocol-level information but does not make
vendor-specific assumptions about the message body.

Vendor/application-specific interpretation should happen later through
source profiles and normalization rules.
"""

import re
from typing import Any


# ---------------------------------------------------------------------------
# Syslog severity
# ---------------------------------------------------------------------------

SEVERITY_NAMES = {
    0: "Emergency",
    1: "Alert",
    2: "Critical",
    3: "Error",
    4: "Warning",
    5: "Notice",
    6: "Informational",
    7: "Debug",
}


# ---------------------------------------------------------------------------
# Syslog facility
# ---------------------------------------------------------------------------

FACILITY_NAMES = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    12: "ntp",
    13: "security",
    14: "console",
    15: "solaris-cron",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}


# ---------------------------------------------------------------------------
# PRI parsing
# ---------------------------------------------------------------------------

PRI_PATTERN = re.compile(r"^<([0-9]{1,3})>")


def parse_pri(value: str) -> tuple[int, int, str, str]:
    """
    Parse the Syslog PRI value.

    PRI = facility * 8 + severity

    Returns:
        pri_value
        facility
        facility_name
        severity
        severity_name
    """

    match = PRI_PATTERN.match(value)

    if not match:
        raise ValueError("Invalid Syslog PRI value")

    pri = int(match.group(1))

    # RFC 5424 permits PRI values from 0 to 191.
    if not 0 <= pri <= 191:
        raise ValueError(f"Syslog PRI out of range: {pri}")

    facility = pri >> 3
    severity = pri & 0x07

    return (
        pri,
        facility,
        FACILITY_NAMES.get(facility, "unknown"),
        SEVERITY_NAMES[severity],
    )


# ---------------------------------------------------------------------------
# Structured Data
# ---------------------------------------------------------------------------

def _unescape_structured_value(value: str) -> str:
    """
    RFC 5424 structured-data escaping.

    Escaped characters:
        \\"
        \\\\
        \\]
    """

    return (
        value
        .replace(r"\\", "\\")
        .replace(r"\"", '"')
        .replace(r"\]", "]")
    )


def parse_structured_data(value: str) -> list[dict[str, Any]]:
    """
    Parse RFC 5424 STRUCTURED-DATA.

    Example:

        [exampleSDID@32473 iut="3" eventSource="Application"]

    becomes:

        [
            {
                "id": "exampleSDID@32473",
                "params": {
                    "iut": "3",
                    "eventSource": "Application"
                }
            }
        ]
    """

    if value == "-" or not value:
        return []

    elements: list[dict[str, Any]] = []

    index = 0
    length = len(value)

    while index < length:

        if value[index] != "[":
            raise ValueError("Malformed Syslog structured data")

        end = index + 1
        escaped = False

        while end < length:
            char = value[end]

            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "]":
                break

            end += 1

        if end >= length:
            raise ValueError("Unterminated Syslog structured-data element")

        element_text = value[index + 1:end]

        # Split the SD-ID from its parameters.
        parts = element_text.split(" ", 1)

        sd_id = parts[0]

        if not sd_id:
            raise ValueError("Missing structured-data ID")

        params: dict[str, str] = {}

        if len(parts) == 2:
            parameter_text = parts[1]

            parameter_pattern = re.compile(
                r'([^\s=]+)="((?:\\.|[^"])*)"'
            )

            position = 0

            for match in parameter_pattern.finditer(parameter_text):

                # Anything between parameters that isn't whitespace means
                # the structured data is malformed.
                between = parameter_text[position:match.start()]

                if between.strip():
                    raise ValueError(
                        "Malformed structured-data parameters"
                    )

                name = match.group(1)
                raw_value = match.group(2)

                params[name] = _unescape_structured_value(raw_value)

                position = match.end()

            if parameter_text[position:].strip():
                raise ValueError(
                    "Malformed structured-data parameters"
                )

        elements.append(
            {
                "id": sd_id,
                "params": params,
            }
        )

        index = end + 1

    return elements


# ---------------------------------------------------------------------------
# RFC 5424 parser
# ---------------------------------------------------------------------------

def _parse_rfc5424(log: str) -> dict[str, Any]:
    """
    Parse an RFC 5424 Syslog message.

    Expected structure:

        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
        STRUCTURED-DATA [MSG]
    """

    # Remove PRI first.
    pri_match = PRI_PATTERN.match(log)

    if not pri_match:
        raise ValueError("Missing Syslog PRI")

    pri_end = pri_match.end()

    rest = log[pri_end:]

    # RFC 5424 header consists of:
    #
    # VERSION
    # TIMESTAMP
    # HOSTNAME
    # APP-NAME
    # PROCID
    # MSGID
    #
    # All are space separated.
    header_match = re.match(
        r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+",
        rest,
    )

    if not header_match:
        raise ValueError("Invalid RFC 5424 Syslog header")

    version = int(header_match.group(1))

    if version <= 0:
        raise ValueError("Invalid Syslog version")

    timestamp = header_match.group(2)
    hostname = header_match.group(3)
    app_name = header_match.group(4)
    procid = header_match.group(5)
    msgid = header_match.group(6)

    remaining = rest[header_match.end():]

    # STRUCTURED-DATA
    if remaining.startswith("-"):
        structured_data_raw = "-"
        remaining = remaining[1:]

    elif remaining.startswith("["):
        # Find the end of all consecutive SD-ELEMENT blocks.
        sd_end = 0

        while sd_end < len(remaining):

            if remaining[sd_end] != "[":
                break

            index = sd_end + 1
            escaped = False

            while index < len(remaining):

                char = remaining[index]

                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == "]":
                    break

                index += 1

            if index >= len(remaining):
                raise ValueError(
                    "Unterminated RFC 5424 structured data"
                )

            sd_end = index + 1

        structured_data_raw = remaining[:sd_end]
        remaining = remaining[sd_end:]

    else:
        raise ValueError(
            "Invalid RFC 5424 structured-data field"
        )

    # Optional MSG is separated from structured data by one space.
    message = remaining[1:] if remaining.startswith(" ") else ""

    pri, facility, facility_name, severity_name = parse_pri(log)

    severity = pri & 0x07

    return {
        "protocol": "Syslog",
        "version": version,

        "pri": pri,

        "facility": facility,
        "facility_name": facility_name,

        "severity": severity,
        "severity_name": severity_name,

        "timestamp": None if timestamp == "-" else timestamp,

        "hostname": None if hostname == "-" else hostname,
        "app_name": None if app_name == "-" else app_name,
        "procid": None if procid == "-" else procid,
        "msgid": None if msgid == "-" else msgid,

        "structured_data": parse_structured_data(
            structured_data_raw
        ),

        "message": message,

        "raw_message": log,
    }


# ---------------------------------------------------------------------------
# Legacy / BSD Syslog parser
# ---------------------------------------------------------------------------

LEGACY_PATTERN = re.compile(
    r"^"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+"
    r"\d{1,2}\s+"
    r"\d{2}:\d{2}:\d{2})"
    r"\s+"
    r"(?P<hostname>\S+)"
    r"\s+"
    r"(?P<message>.*)"
    r"$"
)


def _parse_legacy_syslog(log: str) -> dict[str, Any]:
    """
    Parse a common BSD/legacy Syslog format.

    Example:

        <34>Sep  9 23:20:10 firewall01 sshd:
        Failed login for admin from 192.168.1.20

    Legacy Syslog has historically had significant implementation
    variation, so the parser intentionally preserves the remainder
    of the message instead of making vendor-specific assumptions.
    """

    pri, facility, facility_name, severity_name = parse_pri(log)

    severity = pri & 0x07

    # Remove PRI.
    message_without_pri = PRI_PATTERN.sub("", log, count=1)

    match = LEGACY_PATTERN.match(message_without_pri)

    if not match:
        # Some devices use <PRI> followed by an arbitrary message.
        # We still preserve it rather than throwing away the event.
        return {
            "protocol": "Syslog",
            "version": None,

            "pri": pri,

            "facility": facility,
            "facility_name": facility_name,

            "severity": severity,
            "severity_name": severity_name,

            "timestamp": None,
            "hostname": None,
            "app_name": None,
            "procid": None,
            "msgid": None,

            "structured_data": [],

            "message": message_without_pri,

            "raw_message": log,
        }

    timestamp = match.group("timestamp")
    hostname = match.group("hostname")
    message = match.group("message")

    # Try to separate a common TAG/application prefix:
    #
    # sshd[1234]:
    # sshd:
    #
    # This is deliberately conservative.
    app_name = None
    procid = None

    tag_match = re.match(
        r"^(?P<tag>[A-Za-z0-9_.@/-]+)"
        r"(?:\[(?P<pid>[^\]]+)\])?"
        r":\s*"
        r"(?P<body>.*)$",
        message,
    )

    if tag_match:
        app_name = tag_match.group("tag")
        procid = tag_match.group("pid")
        message = tag_match.group("body")

    return {
        "protocol": "Syslog",
        "version": None,

        "pri": pri,

        "facility": facility,
        "facility_name": facility_name,

        "severity": severity,
        "severity_name": severity_name,

        "timestamp": timestamp,

        "hostname": hostname,
        "app_name": app_name,
        "procid": procid,
        "msgid": None,

        "structured_data": [],

        "message": message,

        "raw_message": log,
    }


# ---------------------------------------------------------------------------
# Public parser
# ---------------------------------------------------------------------------

def parse_syslog(log: str) -> dict[str, Any]:
    """
    Parse a Syslog message.

    The function first validates the input and PRI, then determines whether
    the message appears to be RFC 5424 or legacy/BSD style.

    Returns a consistent dictionary regardless of Syslog variant.
    """

    if not isinstance(log, str):
        raise TypeError("Syslog message must be a string")

    log = log.strip()

    if not log:
        raise ValueError("Syslog message is empty")

    if not PRI_PATTERN.match(log):
        raise ValueError("Syslog message must start with <PRI>")

    # RFC 5424 messages contain a VERSION immediately after PRI.
    #
    # Example:
    # <165>1 2003-10-11T22:14:15.003Z ...
    #
    # Legacy messages normally begin with a month:
    #
    # <34>Sep  9 23:20:10 ...
    after_pri = PRI_PATTERN.sub("", log, count=1)

    if re.match(r"^\d+\s+", after_pri):
        return _parse_rfc5424(log)

    return _parse_legacy_syslog(log)


# ---------------------------------------------------------------------------
# Local parser tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    test_messages = [

        # RFC 5424
        '<165>1 2003-10-11T22:14:15.003Z '
        'mymachine.example.com su - ID47 - '
        "'su root' failed for lonvick on /dev/pts/8",

        # RFC 5424 with structured data
        '<165>1 2003-10-11T22:14:15.003Z '
        'firewall01 firewall 1234 FW001 '
        '[exampleSDID@32473 iut="3" eventSource="Firewall" '
        'eventID="1011"] Connection blocked',

        # Legacy/BSD style
        '<34>Sep  9 23:20:10 firewall01 sshd[1234]: '
        'Failed login for admin from 192.168.1.20',

        # Legacy without application prefix
        '<134>Sep  9 23:21:10 firewall01 '
        'DENY src=10.0.0.5 dst=10.0.0.10',
    ]

    for message in test_messages:

        print("=" * 70)
        print("RAW:")
        print(message)

        try:
            parsed = parse_syslog(message)

            print("\nPARSED:")

            for key, value in parsed.items():
                print(f"{key}: {value}")

        except Exception as exc:
            print("ERROR:", type(exc).__name__, str(exc))