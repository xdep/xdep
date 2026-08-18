"""Where the honeypot number gets published, and how calls are attributed back.

Every channel here is one the operator controls or is invited into. Each gets
its own DID, so an inbound call names its own source: the number that was dialled
*is* the attribution key. That is more precise than any tagging scheme, and it is
what makes "which seeding channel actually produces scam calls" an answerable
question rather than a guess.

Posting the number to sites the operator does not own — classified ads, forums,
marketplace listings — is not a supported channel. It is off the list because it
is spam: it violates those sites' terms, and the cost lands on their moderators
and readers rather than on the scammers being studied.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .. import db


@dataclass(frozen=True)
class ChannelKind:
    slug: str
    label: str
    rationale: str
    typical_latency: str


#: Supported seeding channels, roughly in order of how much traffic they tend to
#: produce per unit of effort.
KINDS: dict[str, ChannelKind] = {
    "lead_form_optin": ChannelKind(
        "lead_form_optin",
        "Lead-generation form opt-in",
        "The operator enters their own honeypot number into quote/offer forms that "
        "resell leads. Consent is the operator's to give for their own line, and "
        "these lists are the direct feedstock for warranty, insurance, and solar "
        "call centres.",
        "hours to days",
    ),
    "owned_web": ChannelKind(
        "owned_web",
        "Page on a domain the operator owns",
        "A crawlable page carrying the number. Scraper bots harvest it the same "
        "way they harvest any contact page. No third party's terms are involved.",
        "days to weeks",
    ),
    "inbound_reply": ChannelKind(
        "inbound_reply",
        "Reply to an unsolicited contact",
        "The number is given out only in response to a scam call, text, or email "
        "that arrived first. Replying to someone who contacted you is not "
        "solicitation, and it reaches the operators directly.",
        "minutes to hours",
    ),
    "reporting_feed": ChannelKind(
        "reporting_feed",
        "Shared with a reporting or research programme",
        "Carriers, regulators, and academic robocall projects run honeypot "
        "exchanges. Numbers contributed there get dialled by the traffic those "
        "programmes already track.",
        "days",
    ),
    "owned_profile": ChannelKind(
        "owned_profile",
        "Contact field on the operator's own account",
        "The number in a profile the operator legitimately holds. Publishing your "
        "own contact detail in your own profile is within any platform's terms; "
        "bulk-posting content is not.",
        "weeks",
    ),
    "printed": ChannelKind(
        "printed",
        "Physical material the operator controls",
        "Signage, business cards, a vehicle decal. Slow, but it catches "
        "locally-sourced fraud that never touches an online list.",
        "weeks to months",
    ),
    "direct_share": ChannelKind(
        "direct_share",
        "Given directly to a partner",
        "Handed to a named collaborator, carrier contact, or investigator. Useful "
        "as a control: this line should stay quiet, so any traffic on it is a leak.",
        "n/a (control line)",
    ),
}

#: Rejected on purpose, with the reason, so the refusal is legible in the code
#: rather than only in a README nobody opens.
UNSUPPORTED: dict[str, str] = {
    "classified_ads": "Posting ads to classifieds you do not own is spam and breaks their terms.",
    "forum_posting": "Automated forum posting is spam and lands on volunteer moderators.",
    "marketplace_listing": "Fake listings defraud buyers who respond in good faith.",
    "comment_sections": "Comment-section drops are spam regardless of what the payload is.",
}


class UnsupportedChannel(ValueError):
    pass


def register(
    conn: sqlite3.Connection,
    slug: str,
    name: str,
    kind: str,
    did: str,
    url: str | None = None,
    notes: str | None = None,
) -> int:
    """Register one seeding channel and bind a DID to it."""
    if kind in UNSUPPORTED:
        raise UnsupportedChannel(f"{kind}: {UNSUPPORTED[kind]}")
    if kind not in KINDS:
        raise UnsupportedChannel(
            f"unknown channel kind {kind!r}; supported: {', '.join(sorted(KINDS))}"
        )
    if not did.startswith("+"):
        raise ValueError("did must be in E.164 form, e.g. +15550001111")
    return db.upsert_channel(conn, slug, name, kind, did=did, url=url, notes=notes)


def attribute(conn: sqlite3.Connection, dialled_did: str) -> int | None:
    """Map the number that was dialled back to the channel that published it."""
    row = db.channel_for_did(conn, dialled_did)
    return int(row["id"]) if row else None


def effectiveness(conn: sqlite3.Connection) -> list[dict[str, object]]:
    """Per-channel yield: calls, distinct callers, and time to first contact.

    ``hours_to_first_call`` is the honest measure of a channel's latency — how
    long the number sat published before anything dialled it.
    """
    rows = conn.execute(
        """
        SELECT ch.slug, ch.kind, ch.did, ch.published_at,
               COUNT(c.id)                    AS calls,
               COUNT(DISTINCT c.from_number)  AS unique_callers,
               MIN(c.started_at)              AS first_call
        FROM channels ch
        LEFT JOIN calls c ON c.channel_id = ch.id
        GROUP BY ch.id
        ORDER BY calls DESC, ch.slug
        """
    ).fetchall()

    out: list[dict[str, object]] = []
    for row in rows:
        entry = dict(row)
        entry["hours_to_first_call"] = _hours_between(
            row["published_at"], row["first_call"]
        )
        out.append(entry)
    return out


def _hours_between(start: str | None, end: str | None) -> float | None:
    if not start or not end:
        return None
    from datetime import datetime

    delta = datetime.fromisoformat(end) - datetime.fromisoformat(start)
    return round(delta.total_seconds() / 3600, 2)
