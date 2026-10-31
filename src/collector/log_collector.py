
import json

from pathlib import Path

from src.collector.event_parser import parse_event


def collect_events(file_path):
    """
    Read JSONL events, validate them and separate invalid records.
    """

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    valid_events = []
    rejected_events = []

    with path.open("r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):

            if not line.strip():
                continue

            try:
                raw_event = json.loads(line)
                event = parse_event(raw_event)
                valid_events.append(event)

            except (json.JSONDecodeError, ValueError) as error:
                rejected_events.append({
                    "line": line_number,
                    "error": str(error),
                    "raw": line.strip()
                })

    return {
        "total_valid": len(valid_events),
        "total_rejected": len(rejected_events),
        "events": valid_events,
        "rejected": rejected_events
    }
