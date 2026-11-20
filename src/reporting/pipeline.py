
from src.collector.log_collector import collect_events
from src.reporting.alert_engine import build_alert
from src.detection.brute_force import detect_brute_force
from src.reporting.report_writer import save_report

from src.database.db import (
    initialize_database,
    store_analysis,
)


def process_log_file(
    input_path,
    output_path,
    db_path="data/soclab.db",
):
    """
    Collect events, detect threats, generate alerts,
    save JSON reports and persist investigation data.
    """

    # 1. Collect and validate events
    collection = collect_events(input_path)

    # 2. Run detection rules
    detections = detect_brute_force(collection["events"])

    # 3. Convert detections into standardized alerts
    alerts = [
        build_alert(detection)
        for detection in detections
    ]

    # 4. Initialize the SQLite database
    initialize_database(db_path)

    # 5. Persist events and alerts.
    # Capture the actual IDs returned by the database.
    alerts = store_analysis(
        collection["events"],
        alerts,
        db_path,
    )

    # 6. Export the JSON report using persisted alert IDs
    report_path = save_report(alerts, output_path)

    return {
        "input_file": str(input_path),
        "total_events": collection["total_valid"],
        "rejected_events": collection["total_rejected"],
        "total_alerts": len(alerts),
        "report_file": str(report_path),
        "database_file": str(db_path),
        "alerts": alerts,
        "rejected": collection["rejected"],
    }
