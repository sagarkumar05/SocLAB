# SocLAB — SOC Investigation and Detection Lab

SocLAB is a Python-based Security Operations Center (SOC) investigation project that processes JSONL security logs, detects suspicious authentication activity, and supports alert investigation through a command-line interface.

The project demonstrates log validation, brute-force detection, alert management, SQLite persistence, and investigation history.

## Features

- Security event collection from JSONL files
- Event validation and malformed event handling
- Timestamp normalization to UTC
- Brute-force login detection
- Automated alert generation with severity and evidence
- SQLite database for storing events and alerts
- Alert listing, viewing, updating, and assignment
- Investigation notes and alert history
- Event searching by IP address, event type, and username
- Automated unit testing with pytest

## Detection Rules

| Rule ID | Description | Severity | Status |
|---|---|---|---|
| SOC-AUTH-001 | Multiple failed login attempts | High | Enabled |
| SOC-AUTH-002 | Successful login after failures | Medium | Disabled |
| SOC-NET-001 | Suspicious network connection | Medium | Disabled |
| SOC-PRIV-001 | Privilege escalation activity | Critical | Disabled |
| SOC-SYS-001 | Suspicious system activity | Medium | Disabled |
| SOC-WEB-001 | Suspicious web activity | High | Disabled |

The enabled brute-force detection rule triggers when at least 5 failed login attempts occur within a 5-minute window from the same source IP.

Only SOC-AUTH-001 is currently implemented as an active detection rule. The other rules are listed for reference and are disabled.

## Technology Stack

- Python 3
- SQLite
- JSON / JSONL
- pytest
- Kali Linux

## Project Structure

```text
SocLAB/
├── data/
├── reports/
├── samples/
│   └── logs/
│       ├── auth_events.jsonl
│       └── brute_force.jsonl
├── src/
│   ├── collector/
│   │   ├── event_parser.py
│   │   └── log_collector.py
│   ├── correlation/
│   ├── database/
│   │   └── db.py
│   ├── detection/
│   │   └── brute_force.py
│   └── reporting/
│       ├── alert_engine.py
│       ├── pipeline.py
│       └── report_writer.py
├── tests/
├── soclab.py
├── requirements.txt
└── README.md
