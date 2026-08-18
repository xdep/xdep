"""SQLite storage for the honeypot.

One file, no server, WAL mode so the webhook handler and the classifier worker
can write concurrently. Every table that records inbound activity carries a
``channel_id`` so a call can be attributed back to where the number was
published.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS channels (
    id          INTEGER PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    did         TEXT UNIQUE,
    url         TEXT,
    published_at TEXT,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS callers (
    id          INTEGER PRIMARY KEY,
    e164        TEXT NOT NULL UNIQUE,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    call_count  INTEGER NOT NULL DEFAULT 0,
    sms_count   INTEGER NOT NULL DEFAULT 0,
    carrier     TEXT,
    line_type   TEXT
);

CREATE TABLE IF NOT EXISTS calls (
    id            INTEGER PRIMARY KEY,
    provider_sid  TEXT UNIQUE,
    from_number   TEXT NOT NULL,
    to_number     TEXT NOT NULL,
    channel_id    INTEGER REFERENCES channels(id),
    started_at    TEXT NOT NULL,
    ended_at      TEXT,
    duration_s    INTEGER,
    status        TEXT,
    recording_sid TEXT,
    recording_url TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY,
    provider_sid TEXT UNIQUE,
    from_number  TEXT NOT NULL,
    to_number    TEXT NOT NULL,
    channel_id   INTEGER REFERENCES channels(id),
    body         TEXT NOT NULL,
    received_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transcripts (
    id         INTEGER PRIMARY KEY,
    call_id    INTEGER NOT NULL REFERENCES calls(id) ON DELETE CASCADE,
    text       TEXT NOT NULL,
    source     TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS classifications (
    id           INTEGER PRIMARY KEY,
    subject_type TEXT NOT NULL,
    subject_id   INTEGER NOT NULL,
    category     TEXT NOT NULL,
    confidence   REAL NOT NULL,
    indicators   TEXT NOT NULL DEFAULT '[]',
    summary      TEXT,
    classifier   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    UNIQUE (subject_type, subject_id, classifier)
);

CREATE INDEX IF NOT EXISTS idx_calls_from ON calls(from_number);
CREATE INDEX IF NOT EXISTS idx_calls_started ON calls(started_at);
CREATE INDEX IF NOT EXISTS idx_calls_channel ON calls(channel_id);
CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_number);
CREATE INDEX IF NOT EXISTS idx_class_subject ON classifications(subject_type, subject_id);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


@contextmanager
def session(path: str) -> Iterator[sqlite3.Connection]:
    conn = connect(path)
    try:
        init(conn)
        yield conn
    finally:
        conn.close()


# --- channels -------------------------------------------------------------


def upsert_channel(
    conn: sqlite3.Connection,
    slug: str,
    name: str,
    kind: str,
    did: str | None = None,
    url: str | None = None,
    notes: str | None = None,
) -> int:
    conn.execute(
        """
        INSERT INTO channels (slug, name, kind, did, url, published_at, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(slug) DO UPDATE SET
            name=excluded.name, kind=excluded.kind, did=excluded.did,
            url=excluded.url, notes=excluded.notes
        """,
        (slug, name, kind, did, url, utcnow(), notes),
    )
    row = conn.execute("SELECT id FROM channels WHERE slug=?", (slug,)).fetchone()
    return int(row["id"])


def channel_for_did(conn: sqlite3.Connection, did: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM channels WHERE did=?", (did,)).fetchone()


# --- callers --------------------------------------------------------------


def touch_caller(conn: sqlite3.Connection, e164: str, *, is_sms: bool = False) -> None:
    now = utcnow()
    conn.execute(
        """
        INSERT INTO callers (e164, first_seen, last_seen, call_count, sms_count)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(e164) DO UPDATE SET
            last_seen = excluded.last_seen,
            call_count = callers.call_count + excluded.call_count,
            sms_count  = callers.sms_count  + excluded.sms_count
        """,
        (e164, now, now, 0 if is_sms else 1, 1 if is_sms else 0),
    )


# --- calls & messages -----------------------------------------------------


def record_call_start(
    conn: sqlite3.Connection,
    provider_sid: str,
    from_number: str,
    to_number: str,
    channel_id: int | None,
) -> int:
    conn.execute(
        """
        INSERT INTO calls (provider_sid, from_number, to_number, channel_id,
                           started_at, status)
        VALUES (?, ?, ?, ?, ?, 'in-progress')
        ON CONFLICT(provider_sid) DO NOTHING
        """,
        (provider_sid, from_number, to_number, channel_id, utcnow()),
    )
    touch_caller(conn, from_number)
    row = conn.execute(
        "SELECT id FROM calls WHERE provider_sid=?", (provider_sid,)
    ).fetchone()
    return int(row["id"])


def record_call_end(
    conn: sqlite3.Connection,
    provider_sid: str,
    status: str,
    duration_s: int | None,
) -> None:
    conn.execute(
        "UPDATE calls SET ended_at=?, status=?, duration_s=? WHERE provider_sid=?",
        (utcnow(), status, duration_s, provider_sid),
    )


def attach_recording(
    conn: sqlite3.Connection, provider_sid: str, recording_sid: str, url: str
) -> None:
    conn.execute(
        "UPDATE calls SET recording_sid=?, recording_url=? WHERE provider_sid=?",
        (recording_sid, url, provider_sid),
    )


def record_message(
    conn: sqlite3.Connection,
    provider_sid: str,
    from_number: str,
    to_number: str,
    body: str,
    channel_id: int | None,
) -> int:
    conn.execute(
        """
        INSERT INTO messages (provider_sid, from_number, to_number, channel_id,
                              body, received_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(provider_sid) DO NOTHING
        """,
        (provider_sid, from_number, to_number, channel_id, body, utcnow()),
    )
    touch_caller(conn, from_number, is_sms=True)
    row = conn.execute(
        "SELECT id FROM messages WHERE provider_sid=?", (provider_sid,)
    ).fetchone()
    return int(row["id"])


def add_transcript(
    conn: sqlite3.Connection, call_id: int, text: str, source: str
) -> int:
    cur = conn.execute(
        "INSERT INTO transcripts (call_id, text, source, created_at) VALUES (?,?,?,?)",
        (call_id, text, source, utcnow()),
    )
    return int(cur.lastrowid)


def save_classification(
    conn: sqlite3.Connection,
    subject_type: str,
    subject_id: int,
    category: str,
    confidence: float,
    indicators: list[str],
    summary: str | None,
    classifier: str,
) -> None:
    conn.execute(
        """
        INSERT INTO classifications (subject_type, subject_id, category, confidence,
                                     indicators, summary, classifier, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(subject_type, subject_id, classifier) DO UPDATE SET
            category=excluded.category, confidence=excluded.confidence,
            indicators=excluded.indicators, summary=excluded.summary,
            created_at=excluded.created_at
        """,
        (
            subject_type,
            subject_id,
            category,
            confidence,
            json.dumps(indicators),
            summary,
            classifier,
            utcnow(),
        ),
    )


def unclassified_calls(conn: sqlite3.Connection, classifier: str) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            """
            SELECT t.id AS transcript_id, t.call_id, t.text, c.from_number
            FROM transcripts t
            JOIN calls c ON c.id = t.call_id
            WHERE NOT EXISTS (
                SELECT 1 FROM classifications k
                WHERE k.subject_type='call' AND k.subject_id=t.call_id
                  AND k.classifier=?
            )
            """,
            (classifier,),
        )
    )


def stats(conn: sqlite3.Connection) -> dict[str, Any]:
    """The headline numbers: how many distinct people called, and from where."""
    def scalar(sql: str) -> int:
        row = conn.execute(sql).fetchone()
        return int(row[0] or 0)

    by_channel = [
        dict(r)
        for r in conn.execute(
            """
            SELECT COALESCE(ch.slug, 'unattributed') AS channel,
                   COUNT(*)                          AS calls,
                   COUNT(DISTINCT c.from_number)     AS unique_callers,
                   MIN(c.started_at)                 AS first_call
            FROM calls c
            LEFT JOIN channels ch ON ch.id = c.channel_id
            GROUP BY ch.slug
            ORDER BY calls DESC
            """
        )
    ]
    by_category = [
        dict(r)
        for r in conn.execute(
            """
            SELECT category, COUNT(*) AS n, AVG(confidence) AS avg_confidence
            FROM classifications
            WHERE subject_type='call'
            GROUP BY category
            ORDER BY n DESC
            """
        )
    ]
    by_day = [
        dict(r)
        for r in conn.execute(
            """
            SELECT substr(started_at, 1, 10) AS day, COUNT(*) AS calls
            FROM calls GROUP BY day ORDER BY day
            """
        )
    ]
    return {
        "total_calls": scalar("SELECT COUNT(*) FROM calls"),
        "total_messages": scalar("SELECT COUNT(*) FROM messages"),
        "unique_callers": scalar("SELECT COUNT(*) FROM callers"),
        "repeat_callers": scalar("SELECT COUNT(*) FROM callers WHERE call_count > 1"),
        "transcribed_calls": scalar("SELECT COUNT(DISTINCT call_id) FROM transcripts"),
        "by_channel": by_channel,
        "by_category": by_category,
        "by_day": by_day,
    }
