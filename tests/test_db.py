import pytest

from honeypot import db
from honeypot.seeding import channels


@pytest.fixture()
def conn():
    connection = db.connect(":memory:")
    db.init(connection)
    yield connection
    connection.close()


def test_repeat_caller_is_counted_once_as_a_caller(conn):
    channel = db.upsert_channel(conn, "s", "Site", "owned_web", did="+15550001111")
    for index in range(3):
        db.record_call_start(conn, f"CA{index}", "+15559990000", "+15550001111", channel)
    stats = db.stats(conn)
    assert stats["total_calls"] == 3
    assert stats["unique_callers"] == 1
    assert stats["repeat_callers"] == 1


def test_replayed_webhook_does_not_duplicate_a_call(conn):
    db.record_call_start(conn, "CA1", "+15559990000", "+15550001111", None)
    db.record_call_start(conn, "CA1", "+15559990000", "+15550001111", None)
    assert db.stats(conn)["total_calls"] == 1


def test_calls_attribute_to_the_number_that_was_dialled(conn):
    channels.register(conn, "forms", "Quote forms", "lead_form_optin", "+15550001111")
    channels.register(conn, "site", "Contact page", "owned_web", "+15550002222")
    db.record_call_start(
        conn, "CA1", "+15557770000", "+15550002222",
        channels.attribute(conn, "+15550002222"),
    )
    by_channel = {row["channel"]: row["calls"] for row in db.stats(conn)["by_channel"]}
    assert by_channel == {"site": 1}


def test_reclassifying_replaces_rather_than_appends(conn):
    call = db.record_call_start(conn, "CA1", "+1555", "+1555", None)
    db.save_classification(conn, "call", call, "unknown", 0.2, [], None, "rules/v1")
    db.save_classification(conn, "call", call, "tech_support", 0.9, ["anydesk"], None, "rules/v1")
    rows = db.stats(conn)["by_category"]
    assert rows == [{"category": "tech_support", "n": 1, "avg_confidence": 0.9}]


def test_two_classifiers_can_disagree_side_by_side(conn):
    call = db.record_call_start(conn, "CA1", "+1555", "+1555", None)
    db.save_classification(conn, "call", call, "unknown", 0.2, [], None, "rules/v1")
    db.save_classification(conn, "call", call, "job_offer", 0.8, [], None, "claude-opus-5")
    assert len(db.stats(conn)["by_category"]) == 2


def test_unclassified_calls_are_per_classifier(conn):
    call = db.record_call_start(conn, "CA1", "+1555", "+1555", None)
    db.add_transcript(conn, call, "hello there this is a long enough transcript", "test")
    assert len(db.unclassified_calls(conn, "rules/v1")) == 1
    db.save_classification(conn, "call", call, "unknown", 0.2, [], None, "rules/v1")
    assert db.unclassified_calls(conn, "rules/v1") == []
    assert len(db.unclassified_calls(conn, "claude-opus-5")) == 1
