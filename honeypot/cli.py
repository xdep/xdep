"""Command line entry point: ``python -m honeypot <command>``."""

from __future__ import annotations

import argparse
import json
import sys

from . import db
from .classify import pipeline, rules
from .config import load
from .seeding import channels, landing

SAMPLES = [
    ("+15551230001", "Hello, this is officer Daniels with the Internal Revenue Service. "
                     "There is an arrest warrant filed against you for back taxes. Do not hang up."),
    ("+15551230002", "We have been trying to reach you concerning your vehicle's extended warranty. "
                     "This is a final notice about your car. Press one to speak with a specialist."),
    ("+15551230003", "Ma'am, I am calling from Microsoft support. Your computer is infected with a virus. "
                     "I need you to install AnyDesk so I can take a look at it."),
    ("+15551230004", "Your package could not be delivered. Please confirm your address at the tracking link "
                     "to reschedule delivery with USPS."),
    ("+15551230001", "This is the Social Security Administration. Your benefits will be suspended today."),
    ("+15551230005", "Hi! Sorry, wrong number. But you seem nice, my name is Amy. Are you on WhatsApp?"),
]


def _add_channel(args) -> int:
    cfg = load()
    with db.session(cfg.db_path) as conn:
        try:
            channels.register(
                conn, args.slug, args.name, args.kind, args.did, args.url, args.notes
            )
        except channels.UnsupportedChannel as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    print(f"registered channel {args.slug} on {args.did}")
    return 0


def _list_channels(_args) -> int:
    cfg = load()
    with db.session(cfg.db_path) as conn:
        rows = channels.effectiveness(conn)
    if not rows:
        print("no channels registered")
        print("\nsupported kinds:")
        for kind in channels.KINDS.values():
            print(f"  {kind.slug:18} {kind.label}  [{kind.typical_latency}]")
        return 0
    width = max(len(str(r["slug"])) for r in rows)
    for row in rows:
        print(
            f"{str(row['slug']):<{width}}  {row['did']:<14} {row['kind']:<18} "
            f"calls={row['calls']:<5} unique={row['unique_callers']:<5} "
            f"first={row['hours_to_first_call'] if row['hours_to_first_call'] is not None else '—'}h"
        )
    return 0


def _kinds(_args) -> int:
    for kind in channels.KINDS.values():
        print(f"{kind.slug}\n  {kind.label} ({kind.typical_latency})\n  {kind.rationale}\n")
    print("not supported:")
    for slug, why in channels.UNSUPPORTED.items():
        print(f"  {slug}: {why}")
    return 0


def _build_site(args) -> int:
    cfg = load()
    with db.session(cfg.db_path) as conn:
        rows = conn.execute(
            "SELECT slug, name, did FROM channels WHERE kind='owned_web' ORDER BY slug"
        ).fetchall()
    if not rows:
        print("no owned_web channels registered; nothing to build", file=sys.stderr)
        return 1
    listings = [
        landing.Listing(
            slug=row["slug"], display_name=row["name"], phone=row["did"], email=args.email
        )
        for row in rows
    ]
    written = landing.build_site(args.out, listings, args.base_url, args.site_name)
    for path in written:
        print(path)
    return 0


def _classify(_args) -> int:
    cfg = load()
    with db.session(cfg.db_path) as conn:
        print(pipeline.run(conn, cfg))
    return 0


def _stats(args) -> int:
    cfg = load()
    with db.session(cfg.db_path) as conn:
        data = db.stats(conn)
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    print(f"calls          {data['total_calls']}")
    print(f"unique callers {data['unique_callers']} ({data['repeat_callers']} repeat)")
    print(f"texts          {data['total_messages']}")
    print(f"transcribed    {data['transcribed_calls']}")
    if data["by_channel"]:
        print("\nby channel:")
        for row in data["by_channel"]:
            print(f"  {row['channel']:<20} {row['calls']:>4} calls, {row['unique_callers']:>3} callers")
    if data["by_category"]:
        print("\nby category:")
        for row in data["by_category"]:
            print(f"  {row['category']:<26} {row['n']:>4}  (avg conf {row['avg_confidence']:.2f})")
    return 0


def _seed_demo(args) -> int:
    """Load synthetic transcripts so the dashboard and classifier can be
    exercised before a real line is connected."""
    cfg = load()
    with db.session(cfg.db_path) as conn:
        channel_id = channels.attribute(conn, args.did)
        if channel_id is None:
            channel_id = channels.register(
                conn, "demo", "Demo line", "owned_web", args.did, notes="synthetic data"
            )
        for index, (caller, text) in enumerate(SAMPLES):
            sid = f"DEMO{index:04d}"
            call_id = db.record_call_start(conn, sid, caller, args.did, channel_id)
            db.record_call_end(conn, sid, "completed", 30 + index * 7)
            db.add_transcript(conn, call_id, text, "demo")
            result = rules.classify(text)
            db.save_classification(
                conn, "call", call_id, result.category, result.confidence,
                result.indicators, result.summary, result.classifier,
            )
    print(f"loaded {len(SAMPLES)} synthetic calls on {args.did}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="honeypot", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("channel-add", help="register a seeding channel and its DID")
    add.add_argument("--slug", required=True)
    add.add_argument("--name", required=True)
    add.add_argument("--kind", required=True, choices=sorted(channels.KINDS))
    add.add_argument("--did", required=True, help="E.164 number bound to this channel")
    add.add_argument("--url")
    add.add_argument("--notes")
    add.set_defaults(func=_add_channel)

    sub.add_parser("channels", help="list channels and their yield").set_defaults(
        func=_list_channels
    )
    sub.add_parser("kinds", help="explain the supported seeding channels").set_defaults(
        func=_kinds
    )

    site = sub.add_parser("site", help="build static contact pages for owned_web channels")
    site.add_argument("--out", required=True)
    site.add_argument("--base-url", required=True)
    site.add_argument("--email", required=True)
    site.add_argument("--site-name", default="Contact")
    site.set_defaults(func=_build_site)

    sub.add_parser("classify", help="label transcripts that have no label yet").set_defaults(
        func=_classify
    )

    stats = sub.add_parser("stats", help="print collection statistics")
    stats.add_argument("--json", action="store_true")
    stats.set_defaults(func=_stats)

    demo = sub.add_parser("seed-demo", help="load synthetic calls for local testing")
    demo.add_argument("--did", default="+15550000000")
    demo.set_defaults(func=_seed_demo)

    args = parser.parse_args(argv)
    return int(args.func(args))
