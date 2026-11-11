import pytest

from src.reporting.alert_engine import build_alert


def make_detection():
    return {
        "rule_id": "SOC-AUTH-001",
        "rule_name": "Multiple Failed Login Attempts",
        "severity": "high",
        "source_ip": "10.10.10.25",
        "failed_attempts": 5,
        "evidence": [
            {"event_type": "failed_login"}
        ]
    }


def test_build_alert():
    alert = build_alert(make_detection())

    assert alert["rule_id"] == "SOC-AUTH-001"
    assert alert["severity"] == "high"
    assert alert["status"] == "new"
    assert alert["source_ip"] == "10.10.10.25"
    assert len(alert["alert_id"]) > 0
    assert len(alert["evidence"]) == 1


def test_alert_ids_are_unique():
    first = build_alert(make_detection())
    second = build_alert(make_detection())

    assert first["alert_id"] != second["alert_id"]


def test_rejects_missing_fields():
    with pytest.raises(ValueError):
        build_alert({"rule_id": "SOC-AUTH-001"})
