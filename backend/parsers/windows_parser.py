def parse_windows_event(event):

    return {
        "event_id": event.get("event_id"),
        "source": event.get("source"),
        "timestamp": event.get("timestamp"),
        "computer": event.get("computer"),
        "message_data": event.get("message_data", []),

        "source_ip": event.get("source_ip"),
        "source_port": event.get("source_port"),
        "destination_ip": event.get("destination_ip"),
        "destination_port": event.get("destination_port")
    }