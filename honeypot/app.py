"""HTTP surface: Twilio webhooks plus a read-only dashboard API.

Run with::

    uvicorn honeypot.app:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

from . import db
from .classify import rules
from .config import Config, load
from .seeding import channels
from .telephony import twilio_webhooks as tw

app = FastAPI(title="Scam-call honeypot", docs_url="/api/docs")

_CONFIG = load()
DASHBOARD = Path(__file__).parent / "dashboard" / "index.html"


def get_config() -> Config:
    return _CONFIG


def _conn(cfg: Config):
    conn = db.connect(cfg.db_path)
    db.init(conn)
    return conn


async def _authenticated_form(request: Request, cfg: Config) -> dict[str, str] | None:
    """Return the POST form if the request really came from Twilio, else None.

    Refusing to run unverified is deliberate: these endpoints are public, and an
    unauthenticated writer could poison the dataset the whole project exists to
    collect. Set ``HONEYPOT_VERIFY_SIGNATURES=false`` only for local testing.
    """
    form = {k: str(v) for k, v in (await request.form()).items()}
    if not cfg.verify_signatures:
        return form
    if not cfg.can_verify_signatures:
        return None
    url = f"{cfg.public_base_url}{request.url.path}"
    signature = request.headers.get("X-Twilio-Signature", "")
    if not tw.signature_is_valid(cfg.twilio_auth_token or "", url, form, signature):
        return None
    return form


def _twiml(body: str) -> Response:
    return Response(content=body, media_type="application/xml")


def _denied() -> Response:
    return JSONResponse({"error": "invalid or missing Twilio signature"}, status_code=403)


@app.post("/twilio/voice")
async def inbound_voice(request: Request, cfg: Config = Depends(get_config)):
    form = await _authenticated_form(request, cfg)
    if form is None:
        return _denied()

    conn = _conn(cfg)
    try:
        to_number = form.get("To", "")
        db.record_call_start(
            conn,
            provider_sid=form.get("CallSid", ""),
            from_number=form.get("From", ""),
            to_number=to_number,
            channel_id=channels.attribute(conn, to_number),
        )
    finally:
        conn.close()
    return _twiml(tw.voice_response(cfg))


@app.post("/twilio/status")
async def call_status(request: Request, cfg: Config = Depends(get_config)):
    form = await _authenticated_form(request, cfg)
    if form is None:
        return _denied()

    duration = form.get("CallDuration")
    conn = _conn(cfg)
    try:
        db.record_call_end(
            conn,
            provider_sid=form.get("CallSid", ""),
            status=form.get("CallStatus", "completed"),
            duration_s=int(duration) if duration and duration.isdigit() else None,
        )
    finally:
        conn.close()
    return _twiml(tw.sms_response())


@app.post("/twilio/recording")
async def recording_ready(request: Request, cfg: Config = Depends(get_config)):
    form = await _authenticated_form(request, cfg)
    if form is None:
        return _denied()

    conn = _conn(cfg)
    try:
        db.attach_recording(
            conn,
            provider_sid=form.get("CallSid", ""),
            recording_sid=form.get("RecordingSid", ""),
            url=form.get("RecordingUrl", ""),
        )
    finally:
        conn.close()
    return _twiml(tw.sms_response())


@app.post("/twilio/recording/transcription")
async def transcription_ready(request: Request, cfg: Config = Depends(get_config)):
    form = await _authenticated_form(request, cfg)
    if form is None:
        return _denied()

    text = form.get("TranscriptionText", "")
    conn = _conn(cfg)
    try:
        row = conn.execute(
            "SELECT id FROM calls WHERE provider_sid=?", (form.get("CallSid", ""),)
        ).fetchone()
        if row is None:
            return JSONResponse({"error": "unknown CallSid"}, status_code=404)
        call_id = int(row["id"])
        db.add_transcript(conn, call_id, text, "twilio")
        # Label immediately with the offline engine so the dashboard is never
        # empty; the Claude pass runs as a batch job and overwrites its own row.
        result = rules.classify(text)
        db.save_classification(
            conn, "call", call_id, result.category, result.confidence,
            result.indicators, result.summary, result.classifier,
        )
    finally:
        conn.close()
    return _twiml(tw.sms_response())


@app.post("/twilio/sms")
async def inbound_sms(request: Request, cfg: Config = Depends(get_config)):
    form = await _authenticated_form(request, cfg)
    if form is None:
        return _denied()

    body = form.get("Body", "")
    to_number = form.get("To", "")
    conn = _conn(cfg)
    try:
        message_id = db.record_message(
            conn,
            provider_sid=form.get("MessageSid", ""),
            from_number=form.get("From", ""),
            to_number=to_number,
            body=body,
            channel_id=channels.attribute(conn, to_number),
        )
        result = rules.classify(body)
        db.save_classification(
            conn, "sms", message_id, result.category, result.confidence,
            result.indicators, result.summary, result.classifier,
        )
    finally:
        conn.close()
    # Silence by default: replying confirms the line is live.
    return _twiml(tw.sms_response())


# --- dashboard ------------------------------------------------------------


@app.get("/api/stats")
def api_stats(cfg: Config = Depends(get_config)):
    conn = _conn(cfg)
    try:
        return db.stats(conn)
    finally:
        conn.close()


@app.get("/api/channels")
def api_channels(cfg: Config = Depends(get_config)):
    conn = _conn(cfg)
    try:
        return channels.effectiveness(conn)
    finally:
        conn.close()


@app.get("/api/calls")
def api_calls(limit: int = 100, cfg: Config = Depends(get_config)):
    conn = _conn(cfg)
    try:
        rows = conn.execute(
            """
            SELECT c.id, c.from_number, c.to_number, c.started_at, c.duration_s,
                   c.status, ch.slug AS channel, k.category, k.confidence,
                   k.summary, k.indicators, k.classifier, t.text AS transcript
            FROM calls c
            LEFT JOIN channels ch ON ch.id = c.channel_id
            LEFT JOIN transcripts t ON t.call_id = c.id
            LEFT JOIN classifications k
                   ON k.subject_type='call' AND k.subject_id = c.id
            ORDER BY c.started_at DESC
            LIMIT ?
            """,
            (max(1, min(limit, 1000)),),
        ).fetchall()
        out = []
        for row in rows:
            entry = dict(row)
            entry["indicators"] = json.loads(entry.pop("indicators", "[]") or "[]")
            out.append(entry)
        return out
    finally:
        conn.close()


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return DASHBOARD.read_text("utf-8")
