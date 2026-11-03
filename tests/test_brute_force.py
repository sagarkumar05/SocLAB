
import pytest

from src.detection.brute_force import detect_brute_force


def make_event(minute, source_ip="192.168.1.10",
               event_type="failed_login"):
    return {
        "timestamp": f"2026-10-31T12:{minute:02d}:00+00:00",
        "source": "authentication",
        "event_type": event_type,
        "source_ip": source_ip,
        "username": "admin"
    }


def test_detects_brute_force():
    events = [make_event(minute) for minute in range(5)]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.168.1.10"
    assert alerts[0]["failed_attempts"] == 5
    assert alerts[0]["severity"] == "high"


def test_does_not_alert_below_threshold():
    events = [make_event(minute) for minute in range(4)]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_ignores_successful_logins():
    events = [
        make_event(minute, event_type="successful_login")
        for minute in range(5)
    ]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_does_not_alert_outside_time_window():
    events = [
        make_event(0),
        make_event(10),
        make_event(20),
        make_event(30),
        make_event(40)
    ]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_rejects_invalid_threshold():
    with pytest.raises(ValueError):
        detect_brute_force([], threshold=0)
