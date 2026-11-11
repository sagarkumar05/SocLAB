import json
import pytest

from src.reporting.report_writer import save_report


def test_save_report(tmp_path):
    alerts = [
        {
            "alert_id": "test-alert-001",
            "severity": "high",
            "status": "new"
        }
    ]

    output_path = tmp_path / "reports" / "test_report.json"

    saved_path = save_report(alerts, output_path)

    assert saved_path.exists()

    with saved_path.open("r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["total_alerts"] == 1
    assert report["alerts"][0]["severity"] == "high"


def test_save_empty_report(tmp_path):
    output_path = tmp_path / "empty_report.json"

    save_report([], output_path)

    with output_path.open("r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["total_alerts"] == 0
    assert report["alerts"] == []


def test_reject_non_json_extension(tmp_path):
    output_path = tmp_path / "report.txt"

    with pytest.raises(ValueError):
        save_report([], output_path)
