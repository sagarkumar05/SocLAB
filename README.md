
# SocLAB

A Python-based SOC investigation and detection lab.

SocLAB is an educational security operations project designed to
collect security events, validate logs, detect suspicious activity,
correlate evidence, and generate structured incident reports.

## Current Features

- Security event validation
- Timestamp normalization to UTC
- JSONL log collection
- Malformed event handling
- Automated unit tests

## Technology

- Python
- JSON / JSONL
- pytest
- Kali Linux

## Project Structure

```text
src/
  collector/
  detection/
  correlation/
  reporting/

samples/
  logs/

tests/
simulations/
rules/
reports/
docs/
```

## Run the Tests

```bash
python3 -m pytest -v
```

## Current Status

Milestone 1: Event parsing and log collection.

This project is under active development.
