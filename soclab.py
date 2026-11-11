
import argparse
import sys
from pathlib import Path

from src.reporting.pipeline import process_log_file


def analyze_command(args):
    """Analyze a JSONL log file and generate a SOC report."""

    input_path = Path(args.input)

    if not input_path.is_file():
        print(f"[ERROR] Input file not found: {input_path}")
        return 1

    try:
        result = process_log_file(
            input_path,
            args.output
        )

        print("\n========== SocLAB Analysis ==========")
        print(f"Input file      : {result['input_file']}")
        print(f"Total events    : {result['total_events']}")
        print(f"Rejected events : {result['rejected_events']}")
        print(f"Total alerts    : {result['total_alerts']}")
        print(f"Report saved    : {result['report_file']}")

        for alert in result["alerts"]:
            print("\n[ALERT DETECTED]")
            print(f"Rule       : {alert['rule_name']}")
            print(f"Severity   : {alert['severity'].upper()}")
            print(f"Source IP  : {alert['source_ip']}")
            print(f"Attempts   : {alert['failed_attempts']}")
            print(f"Alert ID   : {alert['alert_id']}")

        print("\n=====================================")
        return 0

    except (ValueError, OSError) as error:
        print(f"[ERROR] {error}")
        return 1


def main():
    parser = argparse.ArgumentParser(
        prog="soclab",
        description="SOC Investigation and Detection Lab"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a JSONL security log file"
    )

    analyze_parser.add_argument(
        "input",
        help="Path to the input JSONL file"
    )

    analyze_parser.add_argument(
        "-o",
        "--output",
        default="reports/soclab_report.json",
        help="Output JSON report path"
    )

    analyze_parser.set_defaults(
        func=analyze_command
    )

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
