
import argparse
import json
import sqlite3
import sys

from pathlib import Path

from src.reporting.pipeline import process_log_file
from src.database.db import (
    DEFAULT_DB,
    add_note,
    assign_analyst,
    get_alert,
    get_alert_history,
    list_alerts,
    list_rules,
    search_events,
    update_alert_status,
)


def analyze_command(args):
    input_path = Path(args.input)

    if not input_path.is_file():
        print(f"[ERROR] Input file not found: {input_path}")
        return 1

    try:
        result = process_log_file(input_path, args.output)

        print("\n========== SocLAB Analysis ==========")
        print(f"Input file      : {result['input_file']}")
        print(f"Total events    : {result['total_events']}")
        print(f"Rejected events : {result['rejected_events']}")
        print(f"Total alerts    : {result['total_alerts']}")
        print(f"Report saved    : {result['report_file']}")

        if "database_file" in result:
            print(f"Database        : {result['database_file']}")

        for alert in result["alerts"]:
            print("\n[ALERT DETECTED]")
            print(f"Rule       : {alert['rule_name']}")
            print(f"Severity   : {alert['severity'].upper()}")
            print(f"Source IP  : {alert['source_ip']}")
            print(f"Attempts   : {alert['failed_attempts']}")
            print(f"Alert ID   : {alert['alert_id']}")

        print("\n=====================================")
        return 0

    except (ValueError, OSError, sqlite3.Error) as error:
        print(f"[ERROR] {error}")
        return 1


def alerts_list_command(args):
    alerts = list_alerts(DEFAULT_DB, args.status)

    if not alerts:
        print("No alerts found.")
        return 0

    print("\n========== SOC Alerts ==========")

    for alert in alerts:
        print(
            f"\nID: {alert['alert_id']}\n"
            f"Rule: {alert['rule_id']} - {alert['rule_name']}\n"
            f"Severity: {alert['severity'].upper()}\n"
            f"Source IP: {alert['source_ip']}\n"
            f"Attempts: {alert['failed_attempts']}\n"
            f"Status: {alert['status']}\n"
            f"Created: {alert['created_at']}"
        )

    print("\n================================")
    return 0


def alerts_show_command(args):
    alert = get_alert(args.alert_id)

    if alert is None:
        print("[ERROR] Alert not found.")
        return 1

    print(json.dumps(alert, indent=4))
    return 0


def alerts_update_command(args):
    try:
        update_alert_status(
            args.alert_id,
            args.status,
            actor=args.actor,
        )

        print(f"[SUCCESS] Alert status set to: {args.status}")
        print(f"Action performed by: {args.actor}")
        return 0

    except ValueError as error:
        print(f"[ERROR] {error}")
        return 1


def alerts_assign_command(args):
    try:
        assign_analyst(args.alert_id, args.analyst)
        print(f"[SUCCESS] Alert assigned to {args.analyst}")
        return 0

    except ValueError as error:
        print(f"[ERROR] {error}")
        return 1


def alerts_note_command(args):
    try:
        add_note(args.alert_id, args.analyst, args.note)
        print("[SUCCESS] Investigation note saved.")
        return 0

    except ValueError as error:
        print(f"[ERROR] {error}")
        return 1


def alerts_history_command(args):
    try:
        history = get_alert_history(args.alert_id)

        if not history:
            print("No history found for this alert.")
            return 0

        print("\n========== Alert Audit History ==========")

        for entry in history:
            print(
                f"\nHistory ID : {entry['id']}\n"
                f"Action     : {entry['action']}\n"
                f"Old Value  : {entry['old_value']}\n"
                f"New Value  : {entry['new_value']}\n"
                f"Actor      : {entry['actor']}\n"
                f"Timestamp  : {entry['created_at']}"
            )

        print("\n=========================================")
        return 0

    except ValueError as error:
        print(f"[ERROR] {error}")
        return 1


def events_search_command(args):
    events = search_events(
        source_ip=args.ip,
        event_type=args.event_type,
        username=args.username,
        limit=args.limit,
    )

    if not events:
        print("No matching events found.")
        return 0

    print(f"\nFound {len(events)} matching events:")

    for event in events:
        print(json.dumps(event["event"], indent=2))

    return 0


def rules_list_command(args):
    rules = list_rules()

    print("\n========== Detection Rules ==========")

    for rule in rules:
        state = "ENABLED" if rule["enabled"] else "DISABLED"

        print(
            f"\nRule ID: {rule['rule_id']}\n"
            f"Description: {rule['description']}\n"
            f"Severity: {rule['severity'].upper()}\n"
            f"Threshold: {rule['threshold']}\n"
            f"Window: {rule['window_minutes']} minutes\n"
            f"Status: {state}"
        )

    print("\n=====================================")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="soclab",
        description="SOC Investigation and Detection Lab",
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # ANALYZE COMMAND
    analyze = commands.add_parser(
        "analyze",
        help="Analyze a JSONL security log file",
    )
    analyze.add_argument("input")
    analyze.add_argument(
        "-o",
        "--output",
        default="reports/soclab_report.json",
    )
    analyze.set_defaults(func=analyze_command)

    # ALERT COMMANDS
    alerts = commands.add_parser(
        "alerts",
        help="Manage security alerts",
    )

    alert_commands = alerts.add_subparsers(
        dest="alert_command",
        required=True,
    )

    alert_list = alert_commands.add_parser("list")
    alert_list.add_argument(
        "--status",
        choices=["new", "in_progress", "resolved", "false_positive"],
    )
    alert_list.set_defaults(func=alerts_list_command)

    alert_show = alert_commands.add_parser("show")
    alert_show.add_argument("alert_id")
    alert_show.set_defaults(func=alerts_show_command)

    alert_update = alert_commands.add_parser("update")
    alert_update.add_argument("alert_id")
    alert_update.add_argument(
        "--status",
        required=True,
        choices=["new", "in_progress", "resolved", "false_positive"],
    )
    alert_update.add_argument(
        "--actor",
        default="system",
        help="Analyst performing the status change",
    )
    alert_update.set_defaults(func=alerts_update_command)

    alert_assign = alert_commands.add_parser("assign")
    alert_assign.add_argument("alert_id")
    alert_assign.add_argument("--analyst", required=True)
    alert_assign.set_defaults(func=alerts_assign_command)

    alert_note = alert_commands.add_parser("note")
    alert_note.add_argument("alert_id")
    alert_note.add_argument("--analyst", required=True)
    alert_note.add_argument("--note", required=True)
    alert_note.set_defaults(func=alerts_note_command)

    alert_history = alert_commands.add_parser(
        "history",
        help="View the audit history of an alert",
    )
    alert_history.add_argument("alert_id")
    alert_history.set_defaults(func=alerts_history_command)

    # EVENT SEARCH COMMAND
    events = commands.add_parser(
        "events",
        help="Search collected security events",
    )

    event_commands = events.add_subparsers(
        dest="event_command",
        required=True,
    )

    event_search = event_commands.add_parser("search")
    event_search.add_argument("--ip")
    event_search.add_argument("--event-type")
    event_search.add_argument("--username")
    event_search.add_argument("--limit", type=int, default=100)
    event_search.set_defaults(func=events_search_command)

    # RULE COMMAND
    rules = commands.add_parser(
        "rules",
        help="View detection rules",
    )

    rule_commands = rules.add_subparsers(
        dest="rule_command",
        required=True,
    )

    rule_list = rule_commands.add_parser("list")
    rule_list.set_defaults(func=rules_list_command)

    args = parser.parse_args()

    try:
        return args.func(args)

    except sqlite3.Error as error:
        print(f"[DATABASE ERROR] {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
