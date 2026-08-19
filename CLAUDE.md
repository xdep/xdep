# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

A scam-call honeypot platform. It publishes phone numbers on channels the
operator controls, captures everything that dials in, transcribes and classifies
it, and attributes each call back to the channel that produced it.

The question the whole design serves: *how many scam callers actually call us,
and which seeding channel produced them.* Attribution is not a nice-to-have — it
is why one DID is bound to one channel.

Note: the root `readme.md` is the owner's GitHub **profile** readme, unrelated to
this project. Do not edit it. Project docs live in `docs/`.

## Layout

```
honeypot/
  config.py               env-driven Config; no secrets in the tree
  db.py                   SQLite schema + every query. Single source of storage truth
  app.py                  FastAPI: Twilio webhooks + read-only dashboard API
  cli.py, __main__.py     python -m honeypot <command>
  telephony/
    twilio_webhooks.py    TwiML generation + X-Twilio-Signature validation
  classify/
    rules.py              offline keyword/weight classifier; owns CATEGORIES
    llm.py                claude-opus-5 classifier, same label set
    pipeline.py           batch runner with degradation to rules
  seeding/
    channels.py           supported channel kinds + per-DID attribution
    landing.py            static contact-page generator for owned domains
  dashboard/index.html    self-contained dashboard, no build step
tests/                    pytest; nothing touches the network
docs/                     README.md, SEEDING.md, LEGAL.md
```

## Commands

```bash
pip install -r requirements.txt
python -m pytest tests -q                    # full suite, ~0.5s, offline
python -m honeypot seed-demo                 # synthetic calls for local work
python -m honeypot stats                     # collection summary
python -m honeypot channels                  # per-channel yield + latency
python -m honeypot kinds                     # what each seeding channel is
python -m honeypot classify                  # label the backlog (cron this)
python -m honeypot site --out ./public --base-url https://example.org --email x@example.org
uvicorn honeypot.app:app --port 8080         # webhooks + dashboard
```

`HONEYPOT_DB=<path>` selects the database for every command. Full env table in
`docs/README.md`.

## Invariants — do not break these

**The recording notice plays before `<Record>`.** `voice_response()` emits the
disclosure first when recording is enabled, and a test asserts the ordering.
This is a legal constraint in all-party-consent jurisdictions, not a style
choice. Never restructure the TwiML to capture audio first.

**Signature verification fails closed.** With `HONEYPOT_VERIFY_SIGNATURES=true`
and no `TWILIO_AUTH_TOKEN`/`HONEYPOT_PUBLIC_URL`, webhooks return 403. These
endpoints are public; an unauthenticated writer could poison the dataset the
project exists to collect. Do not add a "if we can't verify, allow it" path.

**Ad posting to third-party sites is out of scope, permanently.** Automated
posting to classifieds, forums, marketplaces, or comment sections is spam: it
breaks those sites' terms and the cost lands on their moderators and on people
who answer in good faith. `seeding/channels.py:UNSUPPORTED` rejects those kinds
by name with the reason attached. If asked to add one, decline and point at
`lead_form_optin`, which reaches the same call centres faster and keeps
attribution intact. Keep the rejection in code, not only in prose.

**This platform never places outbound calls.** Answering is passive; automated
dialling brings the TCPA into scope. Do not add a dialler.

**One DID per channel.** Attribution keys off the number that was dialled
(`channels.attribute()`). Sharing a DID across channels silently destroys the
measurement.

**Both classifiers share one label set.** `rules.CATEGORIES` is authoritative;
`llm._SCHEMA` constrains Claude to the same enum. Adding a category means adding
it there, and a test enforces that every rule signal maps into the set.
Classifications are keyed `(subject_type, subject_id, classifier)` so the rule
engine and Claude can label the same call side by side and be compared — never
collapse that key.

## Conventions

- **Storage access goes through `db.py`.** Callers get helper functions, not raw
  SQL. Webhook writes are idempotent via `ON CONFLICT DO NOTHING` on the
  provider SID — providers retry, and a replay must not duplicate a call.
- **`config.Config` is frozen and env-driven.** Handlers take it via FastAPI
  `Depends(get_config)`, which is what lets tests override it. Don't read
  `os.environ` from inside a handler.
- **The classifier degrades, never crashes.** A failed Claude request falls back
  to rules for that one transcript so the batch keeps moving; no credentials
  falls back for the whole run and says so in the report.
- **Claude API:** `claude-opus-5`, structured output via
  `output_config.format`, `effort: "low"` (labelling is shallow), server-side
  fallbacks enabled. Thinking stays on — disabling it on Opus 5 causes tool
  calls to leak into visible text.
- **Tests are offline.** The Claude classifier is exercised against a stub
  client; webhook tests sign their own requests. Keep it that way.
- Comments explain *why*, especially where the reason is legal or adversarial.
  Skip comments that restate the code.

## When adding features

Retention/purge jobs, caller-ID enrichment, and an email honeypot are the
obvious next pieces. Before adding anything that engages a caller rather than
logging them (time-wasting bots, fabricated details), read `docs/LEGAL.md` — that
is a different activity with a different risk profile and the platform
deliberately does not do it.
