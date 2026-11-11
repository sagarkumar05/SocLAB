import json

from src.reporting.pipeline import process_log_file


def test_complete_pipeline(tmp_path):
    input_file = tmp_path / "brute_force.jsonl"
    output_file = tmp_path / "reports" / "result.json"

    events = []

    for minute in range(5):
        event = {
            "timestamp": f"2026-10-31T13:0{minute}:00Z",
            "source": "authentication",
            "event_type": "failed_login",
            "source_ip": "10.10.10.25",
            "username": "admin"
        }

        events.append(json.dumps(event))

    input_file.write_text(
        "\n".join(events) + "\n",
        encoding="utf-8"
    )

    result = process_log_file(input_file, output_file)

    assert result["total_events"] == 5
    assert result["rejected_events"] == 0
    assert result["total_alerts"] == 1
    assert output_file.exists()

    with output_file.open("r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["total_alerts"] == 1
    assert report["alerts"][0]["rule_id"] == "SOC-AUTH-001"


def test_pipeline_handles_invalid_events(tmp_path):
    input_file = tmp_path / "invalid.jsonl"
    output_file = tmp_path / "reports" / "result.json"

    input_file.write_text(
        '{"timestamp":"invalid"}\n',
        encoding="utf-8"
    )

    result = process_log_file(input_file, output_file)

    assert result["total_events"] == 0
    assert result["rejected_events"] == 1
    assert result["total_alerts"] == 0

