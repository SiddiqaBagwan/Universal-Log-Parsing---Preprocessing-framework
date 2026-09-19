import logging
import os
import socket

from backend.processing.pipeline import process_event
from backend.database.db import get_db_connection
from backend.processing.persistence import (
    persist_processed_event,
    persist_processing_error,
)


SYSLOG_HOST = os.getenv("SYSLOG_HOST", "0.0.0.0")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "514"))
BUFFER_SIZE = int(os.getenv("SYSLOG_BUFFER_SIZE", "65535"))


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("lognexus.syslog")


# ---------------------------------------------------------------------------
# Source Resolution
# ---------------------------------------------------------------------------

def resolve_source_id(parsed_event):
    """
    Resolve a registered Syslog source using the parsed hostname.

    Returns:
        source_id if the source is registered and active.
        None if the source is unknown.
    """

    hostname = parsed_event.get("hostname")

    if not hostname:
        return None

    conn = get_db_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT source_id
            FROM sources
            WHERE hostname = %s
              AND source_type = 'Syslog'
              AND status = 'active'
            LIMIT 1
            """,
            (hostname,),
        )

        row = cursor.fetchone()

        return row[0] if row else None

    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Syslog Receiver
# ---------------------------------------------------------------------------

class SyslogReceiver:

    def __init__(
        self,
        host=SYSLOG_HOST,
        port=SYSLOG_PORT,
    ):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False

    # -----------------------------------------------------------------------
    # Start Receiver
    # -----------------------------------------------------------------------

    def start(self):
        """
        Start the UDP Syslog receiver.
        """

        self.socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        self.socket.bind(
            (self.host, self.port)
        )

        self.running = True

        logger.info(
            "LogNexus Syslog Receiver started on %s:%s",
            self.host,
            self.port,
        )

        try:

            while self.running:

                data, address = self.socket.recvfrom(
                    BUFFER_SIZE
                )

                raw_log = data.decode(
                    "utf-8",
                    errors="replace",
                )

                logger.info(
                    "Received Syslog from %s:%s",
                    address[0],
                    address[1],
                )

                self.process_message(
                    raw_log,
                    address,
                )

        except KeyboardInterrupt:

            logger.info(
                "Syslog Receiver stopped by user."
            )

        except Exception:

            logger.exception(
                "Syslog Receiver encountered an unexpected error."
            )

        finally:

            self.stop()

    # -----------------------------------------------------------------------
    # Process Message
    # -----------------------------------------------------------------------

    def process_message(
        self,
        raw_log,
        address=None,
    ):
        """
        Process one received Syslog message.

        Flow:

            Receive
                ↓
            Detect
                ↓
            Parse
                ↓
            Normalize
                ↓
            Validate
                ↓
            Resolve Source
                ↓
            Persist
        """

        result = process_event(raw_log)

        # ---------------------------------------------------------------
        # Processing failure
        # ---------------------------------------------------------------

        if not result.success:

            logger.warning(
                "Syslog processing failed | "
                "format=%s | stage=%s | error_type=%s",
                result.detected_format,
                result.error_stage,
                result.error_type,
            )

            try:

                persistence_result = persist_processing_error(
                    event=raw_log,
                    processing_result=result,
                    source_id=None,
                    raw_metadata={
                        "transport": "UDP",
                        "sender_ip": (
                            address[0]
                            if address
                            else None
                        ),
                        "sender_port": (
                            address[1]
                            if address
                            else None
                        ),
                    },
                )

                logger.info(
                    "Syslog processing error persisted | "
                    "raw_event_id=%s | trace_id=%s",
                    persistence_result["raw_event_id"],
                    persistence_result["trace_id"],
                )

            except Exception:

                logger.exception(
                    "Failed to persist Syslog processing error."
                )

            return False

        # ---------------------------------------------------------------
        # Resolve source
        # ---------------------------------------------------------------

        source_id = resolve_source_id(
            result.parsed_event
        )

        # ---------------------------------------------------------------
        # Persist successfully processed event
        # ---------------------------------------------------------------

        try:

            persistence_result = persist_processed_event(
                event=raw_log,
                processing_result=result,
                source_id=source_id,
                raw_metadata={
                    "transport": "UDP",
                    "sender_ip": (
                        address[0]
                        if address
                        else None
                    ),
                    "sender_port": (
                        address[1]
                        if address
                        else None
                    ),
                    "hostname": result.parsed_event.get(
                        "hostname"
                    ),
                    "source_resolution": (
                        "resolved"
                        if source_id is not None
                        else "unresolved"
                    ),
                },
            )

            if source_id is None:

                logger.warning(
                    "Syslog source unresolved | "
                    "hostname=%s | "
                    "raw_event_id=%s | "
                    "trace_id=%s | "
                    "status=pending_source",
                    result.parsed_event.get("hostname"),
                    persistence_result["raw_event_id"],
                    persistence_result["trace_id"],
                )

            else:

                logger.info(
                    "Syslog processed successfully | "
                    "format=%s | "
                    "raw_event_id=%s | "
                    "trace_id=%s | "
                    "source_id=%s",
                    result.detected_format,
                    persistence_result["raw_event_id"],
                    persistence_result["trace_id"],
                    source_id,
                )

            return True

        except Exception:

            logger.exception(
                "Failed to persist processed Syslog event."
            )

            return False

    # -----------------------------------------------------------------------
    # Stop Receiver
    # -----------------------------------------------------------------------

    def stop(self):
        """
        Stop the receiver and close the UDP socket.
        """

        self.running = False

        if self.socket:

            try:
                self.socket.close()

            except Exception:
                pass

            self.socket = None

            logger.info(
                "LogNexus Syslog Receiver stopped."
            )


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    receiver = SyslogReceiver()

    receiver.start()