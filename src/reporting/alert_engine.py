from datetime import datetime, timezone
from uuid import uuid4


def build_alert(detection):
    """
    Convert a detection result into a standardized SOC alert.
    """

    required_fields = {
        "rule_id",
        "rule_name",
        "severity",
        "source_ip",
        "failed_attempts",
        "evidence"
    }

    missing_fields = required_fields - detection.keys()

    if missing_fields:
        raise ValueError(
            f"Detection is missing fields: {sorted(missing_fields)}"
        )

    alert = {
        "alert_id": str(uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "rule_id": detection["rule_id"],
        "rule_name": detection["rule_name"],
        "severity": detection["severity"],
        "source_ip": detection["source_ip"],
        "failed_attempts": detection["failed_attempts"],
        "status": "new",
        "evidence": detection["evidence"]
    }

    return alert
