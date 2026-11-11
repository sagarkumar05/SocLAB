import json
from pathlib import Path


def save_report(alerts, output_path):
    """
    Save SOC alerts as a JSON report.
    """

    path = Path(output_path)

    if path.suffix.lower() != ".json":
        raise ValueError("Report file must use .json extension")

    path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "total_alerts": len(alerts),
        "alerts": alerts
    }

    with path.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=4)

    return path
