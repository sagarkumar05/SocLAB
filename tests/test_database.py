
import pytest

from src.database.db import (
    initialize_database,
    list_rules,
    store_analysis,
    list_alerts,
    get_alert,
    update_alert_status,
    assign_analyst,
    add_note,
    search_events,
    get_alert_history,
)


@pytest.fixture
def database(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)
    return db_path


@pytest.fixture
def sample_data():
    event = {
        "timestamp": "2026-11-12T10:00:00+00:00",
        "source": "authentication",
        "event_type": "failed_login",
        "source_ip": "10.10.10.25",
        "username": "admin",
    }

    alert = {
        "alert_id": "test-alert-001",
        "rule_id": "SOC-AUTH-001",
        "rule_name": "Multiple Failed Login Attempts",
        "severity": "high",
        "source_ip": "10.10.10.25",
        "failed_attempts": 5,
        "status": "new",
        "created_at": "2026-11-12T10:05:00+00:00",
        "evidence": [event],
    }

    return [event], [alert]


def test_database_initialization(database):
    rules = list_rules(database)

    assert len(rules) == 6
    assert rules[0]["rule_id"] == "SOC-AUTH-001"


def test_store_analysis(database, sample_data):
    events, alerts = sample_data

    store_analysis(events, alerts, database)

    saved_alerts = list_alerts(database)

    assert len(saved_alerts) == 1
    assert saved_alerts[0]["alert_id"] == "test-alert-001"

    saved_events = search_events(
        db_path=database,
        source_ip="10.10.10.25",
    )

    assert len(saved_events) == 1


def test_update_alert_status(database, sample_data):
    events, alerts = sample_data
    store_analysis(events, alerts, database)

    update_alert_status(
        "test-alert-001",
        "in_progress",
        database,
    )

    result = get_alert("test-alert-001", database)

    assert result["status"] == "in_progress"
    assert result["investigation"]["status"] == "in_progress"


def test_assign_analyst(database, sample_data):
    events, alerts = sample_data
    store_analysis(events, alerts, database)

    assign_analyst(
        "test-alert-001",
        "Sagar",
        database,
    )

    result = get_alert("test-alert-001", database)

    assert result["investigation"]["assigned_to"] == "Sagar"


def test_add_investigation_note(database, sample_data):
    events, alerts = sample_data
    store_analysis(events, alerts, database)

    add_note(
        "test-alert-001",
        "Sagar",
        "Investigating repeated login failures.",
        database,
    )

    result = get_alert("test-alert-001", database)

    assert len(result["notes"]) == 1
    assert result["notes"][0]["analyst"] == "Sagar"


def test_reject_invalid_status(database, sample_data):
    events, alerts = sample_data
    store_analysis(events, alerts, database)

    with pytest.raises(ValueError):
        update_alert_status(
            "test-alert-001",
            "invalid_status",
            database,
        )


def test_reject_note_for_missing_alert(database):
    with pytest.raises(ValueError):
        add_note(
            "missing-alert",
            "Sagar",
            "Test note",
            database,
        )
def test_duplicate_alert_reuses_existing_id(database, sample_data):
    events, alerts = sample_data

    first_result = store_analysis(events, alerts, database)

    duplicate_alert = alerts[0].copy()
    duplicate_alert["alert_id"] = "different-generated-id"

    second_result = store_analysis(
        events,
        [duplicate_alert],
        database,
    )

    assert first_result[0]["alert_id"] == second_result[0]["alert_id"]
    assert len(list_alerts(database)) == 1


def test_duplicate_alert_preserves_investigation(database, sample_data):
    events, alerts = sample_data

    store_analysis(events, alerts, database)

    update_alert_status(
        "test-alert-001",
        "in_progress",
        database,
    )

    assign_analyst(
        "test-alert-001",
        "Sagar",
        database,
    )

    add_note(
        "test-alert-001",
        "Sagar",
        "Investigating this alert.",
        database,
    )

    duplicate_alert = alerts[0].copy()
    duplicate_alert["alert_id"] = "new-generated-id"

    store_analysis(
        events,
        [duplicate_alert],
        database,
    )

    result = get_alert("test-alert-001", database)

    assert result["status"] == "in_progress"
    assert result["investigation"]["assigned_to"] == "Sagar"
    assert len(result["notes"]) == 1
    assert result["notes"][0]["note"] == "Investigating this alert."


def test_new_evidence_creates_separate_alert(database, sample_data):
    events, alerts = sample_data

    store_analysis(events, alerts, database)

    new_event = {
        "timestamp": "2026-11-12T10:01:00+00:00",
        "source": "authentication",
        "event_type": "failed_login",
        "source_ip": "10.10.10.25",
        "username": "admin",
    }

    new_alert = alerts[0].copy()
    new_alert["alert_id"] = "new-evidence-alert"
    new_alert["evidence"] = [new_event]
    new_alert["failed_attempts"] = 6

    store_analysis(
        events + [new_event],
        [new_alert],
        database,
    )

    assert len(list_alerts(database)) == 2


def test_alert_history_records_all_actions(database, sample_data):
    events, alerts = sample_data
    store_analysis(events, alerts, database)

    update_alert_status(
        "test-alert-001",
        "in_progress",
        database,
        actor="admin-user",
    )

    assign_analyst(
        "test-alert-001",
        "Sagar",
        database,
        actor="team-lead",
    )

    add_note(
        "test-alert-001",
        "Sagar",
        "Investigating repeated login failures.",
        database,
    )

    history = get_alert_history("test-alert-001", database)

    assert len(history) == 3

    assert history[0]["action"] == "status_changed"
    assert history[0]["old_value"] == "new"
    assert history[0]["new_value"] == "in_progress"
    assert history[0]["actor"] == "admin-user"

    assert history[1]["action"] == "analyst_assigned"
    assert history[1]["old_value"] is None
    assert history[1]["new_value"] == "Sagar"
    assert history[1]["actor"] == "team-lead"

    assert history[2]["action"] == "note_added"
    assert history[2]["new_value"] == "Investigating repeated login failures."
    assert history[2]["actor"] == "Sagar"


def test_unchanged_actions_do_not_create_duplicate_history(database, sample_data):
    events, alerts = sample_data
    store_analysis(events, alerts, database)

    # Setting the existing status should not create history.
    update_alert_status(
        "test-alert-001",
        "new",
        database,
        actor="admin-user",
    )

    # First assignment creates one history entry.
    assign_analyst(
        "test-alert-001",
        "Sagar",
        database,
    )

    # Repeating the same assignment should not create another.
    assign_analyst(
        "test-alert-001",
        "Sagar",
        database,
    )

    history = get_alert_history("test-alert-001", database)

    assert len(history) == 1
    assert history[0]["action"] == "analyst_assigned"


def test_history_rejects_missing_alert(database):
    with pytest.raises(ValueError, match="Alert not found"):
        get_alert_history("missing-alert", database)
