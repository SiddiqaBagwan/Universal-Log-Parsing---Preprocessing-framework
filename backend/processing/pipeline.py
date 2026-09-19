"""
LogNexus Processing Pipeline

Responsibilities:
    1. Identify the input format
    2. Select the appropriate parser
    3. Normalize the parsed event
    4. Validate the normalized event
    5. Apply approved Source Profiles for custom sources
    6. Return a structured processing result

AI is used only during Source Profile onboarding.
Approved mappings are reused deterministically during processing.
"""

from dataclasses import dataclass, field
from typing import Any

from format_detector import detect_format

from backend.parsers.windows_parser import parse_windows_event
from backend.parsers.syslog_parser import parse_syslog

from backend.normalization.mapper import (
    normalize_windows_event,
    normalize_syslog_event,
    normalize_profile_event,
)

from backend.validation.models import NormalizedEvent
from backend.database.db import get_db_connection


# ---------------------------------------------------------------------------
# Processing result
# ---------------------------------------------------------------------------

@dataclass
class ProcessingResult:
    success: bool
    detected_format: str
    raw_event: Any

    parsed_event: dict[str, Any] | None = None
    normalized_event: dict[str, Any] | None = None
    validated_event: NormalizedEvent | None = None

    error_stage: str | None = None
    error_type: str | None = None
    error_message: str | None = None

    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Parser registry
# ---------------------------------------------------------------------------

PARSERS = {
    "Syslog": parse_syslog,
    "Windows Event": parse_windows_event,
}


# ---------------------------------------------------------------------------
# Normalizer registry
# ---------------------------------------------------------------------------

NORMALIZERS = {
    "Windows Event": normalize_windows_event,
    "Syslog": normalize_syslog_event,
}


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_event_format(event):
    """
    Detect the format of an incoming event.
    """

    if isinstance(event, str):
        return detect_format(event)

    if isinstance(event, dict):

        if (
            "event_id" in event
            and (
                "message_data" in event
                or "computer" in event
                or "source" in event
            )
        ):
            return "Windows Event"

        if "raw_log" in event:
            raw_log = event["raw_log"]

            if isinstance(raw_log, str):
                return detect_format(raw_log)

    return "Unknown"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_event(event, detected_format):
    """
    Parse an event according to the detected format.
    """

    parser = PARSERS.get(detected_format)

    if parser is None:
        raise ValueError(
            f"No parser registered for format: {detected_format}"
        )

    if isinstance(event, dict) and "raw_log" in event:
        event = event["raw_log"]

    return parser(event)


# ---------------------------------------------------------------------------
# Source Profile lookup
# ---------------------------------------------------------------------------

def get_approved_source_profile(parsed_event):
    """
    Find an approved Source Profile matching the incoming log.

    Matching priority:
    1. Same hostname/device + compatible parser config
    2. Compatible parser config only

    AI is NOT called when an approved profile matches.
    """

    conn = get_db_connection()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    source_profile_id,
                    profile_name,
                    source_type,
                    vendor,
                    format,
                    field_mapping,
                    parser_config,
                    status
                FROM source_profiles
                WHERE status = 'Approved'
                  AND source_type = 'Syslog'
                ORDER BY source_profile_id DESC
            """)

            profiles = cur.fetchall()

        if not profiles:
            return None

        message = parsed_event.get("message", "")
        hostname = parsed_event.get("hostname")

        if not isinstance(message, str):
            return None

        candidates = []

        for profile in profiles:
            parser_config = profile[6] or {}
            delimiter = parser_config.get("delimiter")

            if not delimiter or delimiter not in message:
                continue

            # Count fields using the saved parser configuration.
            field_count = len(message.split(delimiter))

            mapping = profile[5] or []

            # Profile should describe at least the fields it maps.
            mapped_fields = {
                m.get("source_field")
                for m in mapping
                if isinstance(m, dict) and m.get("source_field")
            }

            expected_field_count = len(mapped_fields)

            if expected_field_count > field_count:
                continue

            profile_data = {
                "source_profile_id": profile[0],
                "profile_name": profile[1],
                "source_type": profile[2],
                "vendor": profile[3],
                "format": profile[4],
                "field_mapping": profile[5],
                "parser_config": parser_config,
                "status": profile[7],
            }

            # Prefer a profile whose name/vendor identifies
            # the incoming device.
            profile_text = (
                f"{profile[1] or ''} "
                f"{profile[3] or ''}"
            ).lower()

            if hostname and hostname.lower() in profile_text:
                return profile_data

            candidates.append(profile_data)

        # If exactly one compatible profile exists, reuse it.
        if len(candidates) == 1:
            return candidates[0]

        # Multiple compatible profiles:
        # do not guess. This prevents incorrect normalization.
        return None

    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Profile field extraction
# ---------------------------------------------------------------------------

def extract_profile_fields(parsed_event, parser_config=None):
    """
    Extract positional fields from a parsed Syslog message.

    Example:

        timestamp|device|action|source_ip|destination_ip|protocol|src_port|dst_port

    becomes:

        field_1
        field_2
        field_3
        ...
    """

    parser_config = parser_config or {}

    message = parsed_event.get("message")

    if not isinstance(message, str):
        raise ValueError(
            "Source Profile requires a string message."
        )

    delimiter = parser_config.get("delimiter", "|")

    if not delimiter:
        delimiter = "|"

    values = [
        value.strip()
        for value in message.split(delimiter)
    ]

    return {
        f"field_{index}": value
        for index, value in enumerate(values, start=1)
    }


# ---------------------------------------------------------------------------
# Standard normalization
# ---------------------------------------------------------------------------

def normalize_event(
    parsed_event: dict[str, Any],
    detected_format: str,
) -> dict[str, Any]:

    normalizer = NORMALIZERS.get(detected_format)

    if normalizer is None:
        raise ValueError(
            f"No normalizer registered for format: {detected_format}"
        )

    normalized_event = normalizer(parsed_event)

    if not isinstance(normalized_event, dict):
        raise TypeError(
            f"Normalizer for {detected_format} must return a dictionary"
        )

    return normalized_event


# ---------------------------------------------------------------------------
# Source Profile normalization
# ---------------------------------------------------------------------------

def normalize_with_source_profile(
    parsed_event,
    source_profile,
):
    """
    Apply a previously approved Source Profile.

    No AI call happens here.
    """

    parser_config = source_profile.get("parser_config") or {}
    field_mapping = source_profile.get("field_mapping") or []

    parsed_fields = extract_profile_fields(
        parsed_event,
        parser_config,
    )

    normalized = normalize_profile_event(
        parsed_fields,
        field_mapping,
    )

    # Profile metadata
    normalized["source"] = source_profile.get(
        "source_type"
    ) or "Syslog"

    normalized["device"] = (
        normalized.get("device")
        or parsed_event.get("hostname")
    )

    # Store provenance without changing the existing DB schema.
    normalized["extra_data"]["source_profile_id"] = (
        source_profile["source_profile_id"]
    )

    normalized["extra_data"]["source_profile_name"] = (
        source_profile["profile_name"]
    )

    normalized["extra_data"]["profile_based_processing"] = True

    return normalized


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_event(normalized_event):
    """
    Validate normalized event using the central Pydantic model.
    """

    return NormalizedEvent(**normalized_event)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def process_event(event: Any) -> ProcessingResult:

    # ---------------------------------------------------------------
    # 1. Detect
    # ---------------------------------------------------------------

    detected_format = detect_event_format(event)

    if detected_format == "Unknown":
        return ProcessingResult(
            success=False,
            detected_format="Unknown",
            raw_event=event,
            error_stage="detection",
            error_type="UnsupportedFormat",
            error_message="Unable to identify the event format.",
        )

    # ---------------------------------------------------------------
    # 2. Parse
    # ---------------------------------------------------------------

    try:

        parsed_event = parse_event(
            event,
            detected_format,
        )

    except Exception as exc:

        return ProcessingResult(
            success=False,
            detected_format=detected_format,
            raw_event=event,
            error_stage="parsing",
            error_type=type(exc).__name__,
            error_message=str(exc),
        )

    # ---------------------------------------------------------------
    # 3. Normalize
    # ---------------------------------------------------------------

    try:

        source_profile = None

        if detected_format == "Syslog":

            source_profile = get_approved_source_profile(
                parsed_event
            )

        if source_profile:

            normalized_event = normalize_with_source_profile(
                parsed_event,
                source_profile,
            )

            profile_based = True
            profile_id = source_profile["source_profile_id"]

        else:

            normalized_event = normalize_event(
                parsed_event,
                detected_format,
            )

            profile_based = False
            profile_id = None

    except Exception as exc:

        return ProcessingResult(
            success=False,
            detected_format=detected_format,
            raw_event=event,
            parsed_event=parsed_event,
            error_stage="normalization",
            error_type=type(exc).__name__,
            error_message=str(exc),
        )

    # ---------------------------------------------------------------
    # 4. Validate
    # ---------------------------------------------------------------

    try:

        validated_event = validate_event(
            normalized_event
        )

    except Exception as exc:

        return ProcessingResult(
            success=False,
            detected_format=detected_format,
            raw_event=event,
            parsed_event=parsed_event,
            normalized_event=normalized_event,
            error_stage="validation",
            error_type=type(exc).__name__,
            error_message=str(exc),
            metadata={
                "source_profile_id": profile_id,
                "profile_based_processing": profile_based,
            },
        )

    # ---------------------------------------------------------------
    # 5. Success
    # ---------------------------------------------------------------

    return ProcessingResult(
        success=True,
        detected_format=detected_format,
        raw_event=event,
        parsed_event=parsed_event,
        normalized_event=normalized_event,
        validated_event=validated_event,
        metadata={
            "pipeline_version": "1.1",
            "source_profile_id": profile_id,
            "profile_based_processing": profile_based,
        },
    )


# ---------------------------------------------------------------------------
# Local tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    # ===============================================================
    # Test 1: Windows Event
    # ===============================================================

    windows_event = {
        "event_id": 4624,
        "timestamp": "2026-09-12T12:00:00+05:30",
        "source": "Microsoft-Windows-Security-Auditing",
        "computer": "TEST-PC",
        "message_data": [
            {
                "name": "TargetUserName",
                "value": "admin",
            }
        ],
        "source_ip": "192.168.1.20",
        "source_port": "51520",
        "destination_ip": None,
        "destination_port": None,
    }

    print("=" * 70)
    print("WINDOWS EVENT TEST")
    print("=" * 70)

    result = process_event(windows_event)

    print("Success:", result.success)
    print("Format:", result.detected_format)

    if result.success:
        print("Normalized:")
        print(result.validated_event.model_dump())

    else:
        print("Stage:", result.error_stage)
        print("Error:", result.error_message)

    # ===============================================================
    # Test 2: Standard Syslog
    # ===============================================================

    syslog_event = (
        "<165>1 2026-09-12T12:00:00Z "
        "firewall01 firewall 1234 FW001 "
        '[exampleSDID@32473 eventID="1011"] '
        "Connection blocked src=10.0.0.5 dst=10.0.0.10"
    )

    print()
    print("=" * 70)
    print("STANDARD SYSLOG TEST")
    print("=" * 70)

    result = process_event(syslog_event)

    print("Success:", result.success)
    print("Format:", result.detected_format)

    if result.success:
        print("Profile Used:",
              result.metadata.get("source_profile_id"))

        print("Profile Based:",
              result.metadata.get("profile_based_processing"))

        print("Normalized:")
        print(result.validated_event.model_dump())

    else:
        print("Stage:", result.error_stage)
        print("Error:", result.error_message)

    # ===============================================================
    # Test 3: Firewall Source Profile
    # ===============================================================

    firewall_event = (
        "<165>1 2026-09-16T14:30:00Z "
        "firewall01 firewall 1234 FW001 "
        '[exampleSDID@32473 eventID="1011"] '
        "2026-09-16T14:30:00Z|"
        "firewall01|"
        "DENY|"
        "10.0.0.5|"
        "10.0.0.10|"
        "TCP|"
        "51520|"
        "443"
    )

    print()
    print("=" * 70)
    print("FIREWALL PROFILE TEST")
    print("=" * 70)

    result = process_event(firewall_event)

    print("Success:", result.success)
    print("Format:", result.detected_format)

    print(
        "Profile ID:",
        result.metadata.get("source_profile_id")
    )

    print(
        "Profile Based:",
        result.metadata.get("profile_based_processing")
    )

    if result.success:

        print("Normalized:")
        print(result.validated_event.model_dump())

    else:

        print("Stage:", result.error_stage)
        print("Error:", result.error_message)


    print("\n" + "=" * 70)
    print("SECOND FIREWALL LOG - PROFILE REUSE TEST")
    print("=" * 70)

    second_firewall_log = (
        "<165>1 2026-09-16T15:05:22Z firewall01 firewall 5678 FW002 "
        "[exampleSDID@32473 eventID=\"1012\"] "
        "2026-09-16T15:05:22Z|firewall01|ALLOW|10.0.0.25|10.0.0.30|UDP|53521|53"
    )

    result = process_event(second_firewall_log)

    print("Success:", result.success)
    print("Format:", result.detected_format)

    print(
        "Profile ID:",
        result.metadata.get("source_profile_id")
    )

    print(
        "Profile Based:",
        result.metadata.get("profile_based_processing")
    )

    if result.success:
        print("Normalized:")
        print(result.validated_event.model_dump())
    else:
        print("Stage:", result.error_stage)
        print("Error:", result.error_message)