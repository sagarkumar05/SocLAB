
import hashlib
import json
import sqlite3

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_DB = "data/soclab.db"

VALID_STATUSES = {
    "new",
    "in_progress",
    "resolved",
    "false_positive",
}


DEFAULT_RULES = [
    (
        "SOC-AUTH-001",
        "Multiple failed login attempts",
        "high",
        5,
        5,
        1,
        "Detects repeated failed logins from one source IP."
    ),
    (
        "SOC-AUTH-002",
        "Successful login after failures",
        "medium",
        3,
        10,
        0,
        "Detects a successful login after repeated failures."
    ),
    (
        "SOC-NET-001",
        "Suspicious network connection",
        "medium",
        10,
        5,
        0,
        "Placeholder rule for future network detections."
    ),
    (
        "SOC-SYS-001",
        "Suspicious system activity",
        "medium",
        5,
        5,
        0,
        "Placeholder rule for future system detections."
    ),
    (
        "SOC-WEB-001",
        "Suspicious web activity",
        "high",
        5,
        5,
        0,
        "Placeholder rule for future web detections."
    ),
    (
        "SOC-PRIV-001",
        "Privilege escalation activity",
        "critical",
        1,
        5,
        0,
        "Placeholder rule for future privilege detections."
    ),
]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def database_connection(db_path=DEFAULT_DB):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database(db_path=DEFAULT_DB):
    with database_connection(db_path) as connection:

        connection.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_hash TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                username TEXT,
                raw_event_json TEXT,
                normalized_event_json TEXT NOT NULL,
                collected_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'new'
                    CHECK(status IN (
                        'new',
                        'in_progress',
                        'resolved',
                        'false_positive'
                    )),
                created_at TEXT NOT NULL,
                evidence_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                assigned_to TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(alert_id)
                    REFERENCES alerts(alert_id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS investigation_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                analyst TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(alert_id)
                    REFERENCES alerts(alert_id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS alert_events (
                alert_id TEXT NOT NULL,
                event_id INTEGER NOT NULL,
                PRIMARY KEY(alert_id, event_id),
                FOREIGN KEY(alert_id)
                    REFERENCES alerts(alert_id)
                    ON DELETE CASCADE,
                FOREIGN KEY(event_id)
                    REFERENCES events(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS rules (
                rule_id TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                threshold INTEGER NOT NULL,
                window_minutes INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                assumptions TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alert_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                action TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(alert_id)
                    REFERENCES alerts(alert_id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON events(timestamp);

            CREATE INDEX IF NOT EXISTS idx_events_source_ip
                ON events(source_ip);

            CREATE INDEX IF NOT EXISTS idx_alerts_status
                ON alerts(status);

            CREATE INDEX IF NOT EXISTS idx_notes_alert
                ON investigation_notes(alert_id);

            CREATE INDEX IF NOT EXISTS idx_alerts_rule_ip
                ON alerts(rule_id, source_ip);

            CREATE INDEX IF NOT EXISTS idx_history_alert
                ON alert_history(alert_id);
        """)

        connection.executemany("""
            INSERT OR IGNORE INTO rules (
                rule_id,
                description,
                severity,
                threshold,
                window_minutes,
                enabled,
                assumptions,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            (*rule, utc_now())
            for rule in DEFAULT_RULES
        ])


def _event_hash(event):
    normalized = json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


def _canonical_evidence(evidence):
    return json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":")
    )


def _record_alert_history(
    connection,
    alert_id,
    action,
    old_value,
    new_value,
    actor
):
    connection.execute("""
        INSERT INTO alert_history (
            alert_id,
            action,
            old_value,
            new_value,
            actor,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert_id,
        action,
        old_value,
        new_value,
        actor,
        utc_now()
    ))


def store_analysis(events, alerts, db_path=DEFAULT_DB):
    initialize_database(db_path)

    persisted_alerts = []

    with database_connection(db_path) as connection:

        event_ids = {}

        # Store events without creating duplicates.
        for event in events:
            event_hash = _event_hash(event)

            connection.execute("""
                INSERT OR IGNORE INTO events (
                    event_hash,
                    timestamp,
                    source,
                    event_type,
                    source_ip,
                    username,
                    normalized_event_json,
                    collected_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_hash,
                event["timestamp"],
                event["source"],
                event["event_type"],
                event["source_ip"],
                event.get("username"),
                json.dumps(event, sort_keys=True),
                utc_now()
            ))

            row = connection.execute("""
                SELECT id FROM events
                WHERE event_hash = ?
            """, (event_hash,)).fetchone()

            event_ids[event_hash] = row["id"]

        # Store alerts and prevent duplicate detections.
        for alert in alerts:

            evidence_json = _canonical_evidence(
                alert["evidence"]
            )

            candidates = connection.execute("""
                SELECT alert_id, evidence_json
                FROM alerts
                WHERE rule_id = ? AND source_ip = ?
            """, (
                alert["rule_id"],
                alert["source_ip"]
            )).fetchall()

            existing_alert = None

            for candidate in candidates:
                existing_evidence = _canonical_evidence(
                    json.loads(candidate["evidence_json"])
                )

                if existing_evidence == evidence_json:
                    existing_alert = candidate
                    break

            if existing_alert:
                # Reuse the existing alert ID.
                # Do not overwrite its status or investigation.
                persisted_alert_id = existing_alert["alert_id"]

            else:
                # This is a genuinely new detection.
                persisted_alert_id = alert["alert_id"]

                connection.execute("""
                    INSERT INTO alerts (
                        alert_id,
                        rule_id,
                        rule_name,
                        severity,
                        source_ip,
                        failed_attempts,
                        status,
                        created_at,
                        evidence_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    persisted_alert_id,
                    alert["rule_id"],
                    alert["rule_name"],
                    alert["severity"],
                    alert["source_ip"],
                    alert["failed_attempts"],
                    alert.get("status", "new"),
                    alert["created_at"],
                    evidence_json
                ))

            # Create an investigation only if it does not exist.
            connection.execute("""
                INSERT OR IGNORE INTO investigations (
                    alert_id,
                    status,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?)
            """, (
                persisted_alert_id,
                "new",
                utc_now(),
                utc_now()
            ))

            # Link the evidence events to the alert.
            for evidence in alert["evidence"]:
                evidence_hash = _event_hash(evidence)
                event_id = event_ids.get(evidence_hash)

                if event_id is not None:
                    connection.execute("""
                        INSERT OR IGNORE INTO alert_events (
                            alert_id,
                            event_id
                        )
                        VALUES (?, ?)
                    """, (
                        persisted_alert_id,
                        event_id
                    ))

            # Return the actual persisted alert ID.
            persisted_alert = dict(alert)
            persisted_alert["alert_id"] = persisted_alert_id

            persisted_alerts.append(persisted_alert)

    return persisted_alerts


def list_alerts(db_path=DEFAULT_DB, status=None):
    with database_connection(db_path) as connection:

        if status is not None:
            if status not in VALID_STATUSES:
                raise ValueError("Invalid alert status")

            rows = connection.execute("""
                SELECT * FROM alerts
                WHERE status = ?
                ORDER BY created_at DESC
            """, (status,)).fetchall()

        else:
            rows = connection.execute("""
                SELECT * FROM alerts
                ORDER BY created_at DESC
            """).fetchall()

        return [dict(row) for row in rows]


def get_alert(alert_id, db_path=DEFAULT_DB):
    with database_connection(db_path) as connection:

        row = connection.execute("""
            SELECT * FROM alerts
            WHERE alert_id = ?
        """, (alert_id,)).fetchone()

        if row is None:
            return None

        alert = dict(row)
        alert["evidence"] = json.loads(
            alert.pop("evidence_json")
        )

        investigation = connection.execute("""
            SELECT * FROM investigations
            WHERE alert_id = ?
        """, (alert_id,)).fetchone()

        alert["investigation"] = (
            dict(investigation)
            if investigation else None
        )

        notes = connection.execute("""
            SELECT * FROM investigation_notes
            WHERE alert_id = ?
            ORDER BY created_at, id
        """, (alert_id,)).fetchall()

        alert["notes"] = [
            dict(note) for note in notes
        ]

        return alert


def update_alert_status(
    alert_id,
    status,
    db_path=DEFAULT_DB,
    actor="system"
):
    if status not in VALID_STATUSES:
        raise ValueError("Invalid alert status")

    if not actor or not actor.strip():
        raise ValueError("Actor cannot be empty")

    with database_connection(db_path) as connection:

        current = connection.execute("""
            SELECT status FROM alerts
            WHERE alert_id = ?
        """, (alert_id,)).fetchone()

        if current is None:
            raise ValueError("Alert not found")

        old_status = current["status"]

        # Record only an actual status change.
        if old_status == status:
            return

        now = utc_now()

        connection.execute("""
            UPDATE alerts
            SET status = ?
            WHERE alert_id = ?
        """, (status, alert_id))

        connection.execute("""
            UPDATE investigations
            SET status = ?, updated_at = ?
            WHERE alert_id = ?
        """, (
            status,
            now,
            alert_id
        ))

        _record_alert_history(
            connection,
            alert_id,
            "status_changed",
            old_status,
            status,
            actor.strip()
        )


def add_note(alert_id, analyst, note, db_path=DEFAULT_DB):
    if not analyst or not analyst.strip():
        raise ValueError("Analyst name cannot be empty")

    if not note or not note.strip():
        raise ValueError("Note cannot be empty")

    analyst = analyst.strip()
    note = note.strip()

    with database_connection(db_path) as connection:

        exists = connection.execute("""
            SELECT 1 FROM alerts
            WHERE alert_id = ?
        """, (alert_id,)).fetchone()

        if exists is None:
            raise ValueError("Alert not found")

        now = utc_now()

        connection.execute("""
            INSERT INTO investigation_notes (
                alert_id,
                analyst,
                note,
                created_at
            )
            VALUES (?, ?, ?, ?)
        """, (
            alert_id,
            analyst,
            note,
            now
        ))

        _record_alert_history(
            connection,
            alert_id,
            "note_added",
            None,
            note,
            analyst
        )


def search_events(
    db_path=DEFAULT_DB,
    source_ip=None,
    event_type=None,
    username=None,
    limit=100
):
    if not isinstance(limit, int) or limit < 1 or limit > 10000:
        raise ValueError("Limit must be between 1 and 10000")

    query = "SELECT * FROM events WHERE 1=1"
    parameters = []

    if source_ip is not None:
        query += " AND source_ip = ?"
        parameters.append(source_ip)

    if event_type is not None:
        query += " AND event_type = ?"
        parameters.append(event_type)

    if username is not None:
        query += " AND username = ?"
        parameters.append(username)

    query += " ORDER BY timestamp DESC LIMIT ?"
    parameters.append(limit)

    with database_connection(db_path) as connection:

        rows = connection.execute(
            query,
            parameters
        ).fetchall()

        results = []

        for row in rows:
            item = dict(row)
            item["event"] = json.loads(
                item["normalized_event_json"]
            )
            results.append(item)

        return results


def list_rules(db_path=DEFAULT_DB):
    with database_connection(db_path) as connection:

        rows = connection.execute("""
            SELECT * FROM rules
            ORDER BY rule_id
        """).fetchall()

        return [dict(row) for row in rows]


def assign_analyst(
    alert_id,
    analyst,
    db_path=DEFAULT_DB,
    actor=None
):
    if not analyst or not analyst.strip():
        raise ValueError("Analyst name cannot be empty")

    analyst = analyst.strip()

    if actor is None:
        actor = analyst

    if not actor or not actor.strip():
        raise ValueError("Actor cannot be empty")

    with database_connection(db_path) as connection:

        current = connection.execute("""
            SELECT assigned_to
            FROM investigations
            WHERE alert_id = ?
        """, (alert_id,)).fetchone()

        if current is None:
            raise ValueError("Alert investigation not found")

        old_analyst = current["assigned_to"]

        # Avoid recording a duplicate assignment.
        if old_analyst == analyst:
            return

        connection.execute("""
            UPDATE investigations
            SET assigned_to = ?, updated_at = ?
            WHERE alert_id = ?
        """, (
            analyst,
            utc_now(),
            alert_id
        ))

        _record_alert_history(
            connection,
            alert_id,
            "analyst_assigned",
            old_analyst,
            analyst,
            actor.strip()
        )


def get_alert_history(alert_id, db_path=DEFAULT_DB):
    with database_connection(db_path) as connection:

        exists = connection.execute("""
            SELECT 1 FROM alerts
            WHERE alert_id = ?
        """, (alert_id,)).fetchone()

        if exists is None:
            raise ValueError("Alert not found")

        rows = connection.execute("""
            SELECT *
            FROM alert_history
            WHERE alert_id = ?
            ORDER BY created_at ASC, id ASC
        """, (alert_id,)).fetchall()

        return [dict(row) for row in rows]

