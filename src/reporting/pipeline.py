from datetime import datetime, timezone
from pathlib import Path

from src.collector.log_collector import collect_events
from src.reporting.alert_engine import build_alert
from src.detection.brute_force import detect_brute_force
from src.reporting.report_writer import save_report


def process_log_file(input_path, output_path):
    """
    Collect events, detect threats, generate alerts,
    and save a JSON investigation report.
    """

    collection = collect_events(input_path)

    detections = detect_brute_force(collection["events"])

    alerts = [
        build_alert(detection)
        for detection in detections
    ]

    report_path = save_report(alerts, output_path)

    return {
        "input_file": str(input_path),
        "total_events": collection["total_valid"],
        "rejected_events": collection["total_rejected"],
        "total_alerts": len(alerts),
        "report_file": str(report_path),
        "alerts": alerts,
        "rejected": collection["rejected"]
    }
