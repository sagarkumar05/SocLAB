
from datetime import datetime, timedelta


def detect_brute_force(events, threshold=5, window_minutes=5):
    """
    Detect repeated failed logins from the same source IP.

    Returns one alert per source IP, based on its
    highest-count sliding time window.
    """

    if threshold < 1:
        raise ValueError("Threshold must be at least 1")

    if window_minutes <= 0:
        raise ValueError("Window must be greater than 0")

    grouped_events = {}

    for event in events:
        if event.get("event_type") != "failed_login":
            continue

        source_ip = event.get("source_ip")
        timestamp_value = event.get("timestamp")

        if not source_ip or not timestamp_value:
            raise ValueError("Failed login event needs source_ip and timestamp")

        timestamp = datetime.fromisoformat(
            timestamp_value.replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            raise ValueError("Event timestamp must include a timezone")

        grouped_events.setdefault(source_ip, []).append(
            (timestamp, event)
        )

    alerts = []
    window = timedelta(minutes=window_minutes)

    for source_ip, records in grouped_events.items():
        records.sort(key=lambda record: record[0])

        left = 0
        best_window = []

        for right in range(len(records)):
            while (
                records[right][0] - records[left][0] > window
            ):
                left += 1

            current_window = records[left:right + 1]

            if len(current_window) > len(best_window):
                best_window = current_window

        if len(best_window) >= threshold:
            evidence = [
                event for timestamp, event in best_window
            ]

            alerts.append({
                "rule_id": "SOC-AUTH-001",
                "rule_name": "Multiple Failed Login Attempts",
                "severity": "high",
                "source_ip": source_ip,
                "failed_attempts": len(best_window),
                "threshold": threshold,
                "window_minutes": window_minutes,
                "first_seen": best_window[0][0].isoformat(),
                "last_seen": best_window[-1][0].isoformat(),
                "evidence": evidence
            })

    return alerts

