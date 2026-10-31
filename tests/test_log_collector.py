
from pathlib import Path

from src.collector.log_collector import collect_events


def test_collect_valid_and_invalid_events(tmp_path):
    log_file = tmp_path / "events.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-31T12:30:00Z",'
        '"source":"authentication",'
        '"event_type":"failed_login",'
        '"source_ip":"192.168.1.10"}\n'

        '{"timestamp":"2026-10-31T12:31:00Z",'
        '"source":"authentication",'
        '"event_type":"failed_login"}\n',

        encoding="utf-8"
    )

    result = collect_events(log_file)

    assert result["total_valid"] == 1
    assert result["total_rejected"] == 1


def test_reject_malformed_json(tmp_path):
    log_file = tmp_path / "broken.jsonl"
    log_file.write_text("{invalid json}\n", encoding="utf-8")

    result = collect_events(log_file)

    assert result["total_valid"] == 0
    assert result["total_rejected"] == 1


def test_missing_log_file():
    missing_file = Path("samples/logs/does_not_exist.jsonl")

    try:
        collect_events(missing_file)
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        pass
