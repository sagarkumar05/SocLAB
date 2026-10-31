
import pytest

from src.collector.event_parser import parse_event


def test_parse_valid_event():
    raw_event = {
        "timestamp": "2026-10-31T12:30:00Z",
        "source": "authentication",
        "event_type": "failed_login",
        "source_ip": "192.168.1.10",
        "username": "admin",
    }

    result = parse_event(raw_event)

    assert result["source"] == "authentication"
    assert result["event_type"] == "failed_login"
    assert result["timestamp"] == "2026-10-31T12:30:00+00:00"


def test_reject_missing_fields():
    raw_event = {
        "timestamp": "2026-10-31T12:30:00Z",
        "source": "authentication",
    }

    with pytest.raises(ValueError):
        parse_event(raw_event)


def test_reject_invalid_timestamp():
    raw_event = {
        "timestamp": "not-a-date",
        "source": "authentication",
        "event_type": "failed_login",
        "source_ip": "192.168.1.10",
    }

    with pytest.raises(ValueError):
        parse_event(raw_event)


def test_reject_timestamp_without_timezone():
    raw_event = {
        "timestamp": "2026-10-31T12:30:00",
        "source": "authentication",
        "event_type": "failed_login",
        "source_ip": "192.168.1.10",
    }

    with pytest.raises(ValueError):
        parse_event(raw_event)
