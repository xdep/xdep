import pytest

from honeypot import db
from honeypot.seeding import channels


@pytest.fixture()
def conn():
    connection = db.connect(":memory:")
    db.init(connection)
    yield connection
    connection.close()


@pytest.mark.parametrize("kind", sorted(channels.UNSUPPORTED))
def test_spam_channels_are_refused(conn, kind):
    with pytest.raises(channels.UnsupportedChannel):
        channels.register(conn, "x", "X", kind, "+15550001111")


def test_unknown_kinds_are_refused(conn):
    with pytest.raises(channels.UnsupportedChannel):
        channels.register(conn, "x", "X", "whatever", "+15550001111")


def test_did_must_be_e164(conn):
    with pytest.raises(ValueError):
        channels.register(conn, "x", "X", "owned_web", "555-0111")


def test_effectiveness_reports_latency_to_first_call(conn):
    channels.register(conn, "site", "Contact page", "owned_web", "+15550001111")
    conn.execute("UPDATE channels SET published_at='2026-01-01T00:00:00+00:00'")
    call_id = db.record_call_start(
        conn, "CA1", "+15557770000", "+15550001111", channels.attribute(conn, "+15550001111")
    )
    conn.execute(
        "UPDATE calls SET started_at='2026-01-02T12:00:00+00:00' WHERE id=?", (call_id,)
    )
    row = channels.effectiveness(conn)[0]
    assert row["hours_to_first_call"] == 36.0


def test_a_quiet_channel_reports_no_latency(conn):
    channels.register(conn, "control", "Partner only", "direct_share", "+15550009999")
    row = channels.effectiveness(conn)[0]
    assert row["calls"] == 0
    assert row["hours_to_first_call"] is None
