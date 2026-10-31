
from datetime import datetime, timezone


REQUIRED_FIELDS = {
    "timestamp",
    "source",
    "event_type",
    "source_ip",
}


def parse_event(raw_event):
    """
    Validate a security event and normalize its timestamp.
    """

    if not isinstance(raw_event, dict):
        raise ValueError("Event must be a dictionary")

    missing_fields = REQUIRED_FIELDS - raw_event.keys()

    if missing_fields:
        raise ValueError(
            f"Missing required fields: {sorted(missing_fields)}"
        )

    event = raw_event.copy()

    try:
        timestamp = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )
    except (ValueError, TypeError):
        raise ValueError("Invalid event timestamp")

    if timestamp.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")

    event["timestamp"] = (
        timestamp.astimezone(timezone.utc).isoformat()
    )

    for field in ("source", "event_type", "source_ip"):
        if not isinstance(event[field], str) or not event[field].strip():
            raise ValueError(f"Invalid value for {field}")

    return event
