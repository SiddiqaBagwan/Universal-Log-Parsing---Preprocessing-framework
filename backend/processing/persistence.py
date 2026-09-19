import json
import uuid

from psycopg2.extras import Json

from backend.database.db import get_db_connection


# ---------------------------------------------------------------------------
# Source Metadata
# ---------------------------------------------------------------------------

def get_source_metadata(detected_format):
    """
    Determine common source metadata from the detected format.

    Vendor-specific identification is handled through
    source registration and source profiles.
    """

    if detected_format == "Windows Event":
        return {
            "source_type": "Windows",
            "vendor": "Microsoft",
            "system": "Windows",
        }

    if detected_format == "Syslog":
        return {
            "source_type": "Syslog",
            "vendor": None,
            "system": "Syslog",
        }

    return {
        "source_type": detected_format,
        "vendor": None,
        "system": None,
    }


# ---------------------------------------------------------------------------
# Persist Successful Event
# ---------------------------------------------------------------------------

def persist_processed_event(
    event,
    processing_result,
    source_id=None,
    raw_metadata=None,
):
    """
    Persist a successfully processed event.

    Stores:
        1. Raw event
        2. Normalized event

    Both records share the same trace_id.

    If source_id is unavailable, the event is retained with
    a pending_source processing status so that source onboarding
    can be performed later.
    """

    if not processing_result.success:
        raise ValueError(
            "Cannot persist an unsuccessful processing result."
        )

    validated_event = processing_result.validated_event

    trace_id = str(uuid.uuid4())

    source_metadata = get_source_metadata(
        processing_result.detected_format
    )

    if raw_metadata is None:
        raw_metadata = {}

    processing_status = (
        "processed"
        if source_id is not None
        else "pending_source"
    )

    conn = get_db_connection()
    cursor = conn.cursor()

    try:

        # -----------------------------------------------------------
        # Store RAW event
        # -----------------------------------------------------------

        cursor.execute(
            """
            INSERT INTO raw_events
            (
                source_id,
                trace_id,
                detected_format,
                raw_event,
                raw_metadata,
                processing_status
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING raw_event_id
            """,
            (
                source_id,
                trace_id,
                processing_result.detected_format,
                json.dumps(event),
                Json(raw_metadata),
                processing_status,
            ),
        )

        raw_event_id = cursor.fetchone()[0]

        # -----------------------------------------------------------
        # Store NORMALIZED event
        # -----------------------------------------------------------

        cursor.execute(
                """
            INSERT INTO normalized_events
            (
                raw_event_id,
                trace_id,
                source_id,
                event_id,
                timestamp,
                source_type,
                vendor,
                system,
                device,
                event_type,
                severity,
                source_ip,
                source_port,
                destination_ip,
                destination_port,
                user_id,
                user_name,
                action,
                outcome,
                message,
                extra_data,
                parser_version,
                source_profile_id,
                validation_status
            )
            VALUES
            (
                %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s
            )
            """,
            (
                raw_event_id,
                trace_id,
                source_id,

                validated_event.event_id,
                validated_event.timestamp,

                source_metadata["source_type"],
                source_metadata["vendor"],
                source_metadata["system"],

                validated_event.device,
                validated_event.event_type,
                validated_event.severity,

                validated_event.source_ip,
                validated_event.source_port,

                validated_event.destination_ip,
                validated_event.destination_port,

                validated_event.user_id,
                validated_event.user_name,

                validated_event.action,
                validated_event.outcome,

                json.dumps(validated_event.message),
                json.dumps(validated_event.extra_data),

                "1.0",
                processing_result.metadata.get("source_profile_id"),
                "valid",
            ),
        )

        conn.commit()

        return {
            "trace_id": trace_id,
            "raw_event_id": raw_event_id,
            "source_id": source_id,
            "processing_status": processing_status,
        }

    except Exception:

        conn.rollback()
        raise

    finally:

        cursor.close()
        conn.close()


# ---------------------------------------------------------------------------
# Persist Processing Error
# ---------------------------------------------------------------------------

def persist_processing_error(
    event,
    processing_result,
    source_id=None,
    raw_metadata=None,
):
    """
    Persist an event that failed during processing.

    The raw event is retained and a processing_errors record
    explains where and why processing failed.

    source_id may be None when the source itself is unknown.
    """

    if processing_result.success:
        raise ValueError(
            "Cannot persist a successful processing result as an error."
        )

    trace_id = str(uuid.uuid4())

    if raw_metadata is None:
        raw_metadata = {}

    raw_metadata = {
        **raw_metadata,
        "processing_stage": processing_result.error_stage,
        "error_type": processing_result.error_type,
        "error_message": processing_result.error_message,
    }

    conn = get_db_connection()
    cursor = conn.cursor()

    try:

        # -----------------------------------------------------------
        # Store failed RAW event
        # -----------------------------------------------------------

        cursor.execute(
            """
            INSERT INTO raw_events
            (
                source_id,
                trace_id,
                detected_format,
                raw_event,
                raw_metadata,
                processing_status
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING raw_event_id
            """,
            (
                source_id,
                trace_id,
                processing_result.detected_format,
                json.dumps(event),
                Json(raw_metadata),
                "failed",
            ),
        )

        raw_event_id = cursor.fetchone()[0]

        # -----------------------------------------------------------
        # Store processing error
        # -----------------------------------------------------------

        cursor.execute(
            """
            INSERT INTO processing_errors
            (
                raw_event_id,
                source_id,
                trace_id,
                stage,
                error_type,
                error_message
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                raw_event_id,
                source_id,
                trace_id,
                processing_result.error_stage,
                processing_result.error_type,
                processing_result.error_message,
            ),
        )

        conn.commit()

        return {
            "trace_id": trace_id,
            "raw_event_id": raw_event_id,
            "source_id": source_id,
        }

    except Exception:

        conn.rollback()
        raise

    finally:

        cursor.close()
        conn.close()