# Scam-call honeypot

A platform for measuring inbound fraud traffic: publish a phone number and email
on channels you control, capture everything that dials in, transcribe it,
classify what kind of scam it is, and attribute each call back to the channel
that produced it.

The headline question this answers is *how many scam callers actually call us,
and which seeding channel produced them* — the second half is what makes the
first half useful.

## What it does

| Piece | File | Role |
|---|---|---|
| Webhook API | `honeypot/app.py` | Answers Twilio voice/SMS webhooks, verifies signatures, logs everything |
| TwiML + auth | `honeypot/telephony/twilio_webhooks.py` | Call flow markup and `X-Twilio-Signature` validation |
| Storage | `honeypot/db.py` | Single-file SQLite: channels, callers, calls, messages, transcripts, labels |
| Rule classifier | `honeypot/classify/rules.py` | Offline keyword/weight baseline over 16 scam categories |
| Claude classifier | `honeypot/classify/llm.py` | `claude-opus-5` with a constrained label schema, for calls rules can't read |
| Batch runner | `honeypot/classify/pipeline.py` | Labels the backlog; degrades to rules if Claude is unreachable |
| Channel registry | `honeypot/seeding/channels.py` | The supported seeding channels and per-DID attribution |
| Page generator | `honeypot/seeding/landing.py` | Crawlable contact pages for a domain you own |
| Dashboard | `honeypot/dashboard/index.html` | Calls, callers, per-channel yield, category breakdown |

## Quick start

```bash
pip install -r requirements.txt

# Load synthetic traffic so there is something to look at
HONEYPOT_DB=demo.sqlite3 python -m honeypot seed-demo
HONEYPOT_DB=demo.sqlite3 python -m honeypot stats

# Serve the dashboard and webhooks
HONEYPOT_DB=demo.sqlite3 uvicorn honeypot.app:app --port 8080
```

## Going live

1. **Buy one number per seeding channel.** The number that was dialled *is* the
   attribution key, so channels must not share a DID.

   ```bash
   python -m honeypot kinds          # what each channel is and why it's allowed
   python -m honeypot channel-add --slug quote-forms --name "Insurance quote forms" \
       --kind lead_form_optin --did +15550001111
   ```

2. **Point the provider at this service.** For each number set the voice webhook
   to `POST https://<host>/twilio/voice`, the status callback to
   `/twilio/status`, and the messaging webhook to `/twilio/sms`.

3. **Set the environment.**

   | Variable | Default | Meaning |
   |---|---|---|
   | `HONEYPOT_DB` | `honeypot.sqlite3` | Database path |
   | `TWILIO_AUTH_TOKEN` | — | Required; webhook signature key |
   | `HONEYPOT_PUBLIC_URL` | — | Required; the URL Twilio calls, as Twilio sees it |
   | `HONEYPOT_VERIFY_SIGNATURES` | `true` | Leave on outside local testing |
   | `HONEYPOT_RECORD_CALLS` | `false` | Off until you have read `LEGAL.md` |
   | `HONEYPOT_RECORDING_NOTICE` | see `config.py` | Played before any recording starts |
   | `ANTHROPIC_API_KEY` | — | Optional; without it the rule classifier runs alone |
   | `HONEYPOT_MODEL` | `claude-opus-5` | Classifier model |

4. **Seed the channels** — see `SEEDING.md`.

5. **Label the backlog** on a schedule:

   ```bash
   python -m honeypot classify    # cron this every 15 minutes
   ```

Signature verification fails closed: with `HONEYPOT_VERIFY_SIGNATURES=true` and
no `TWILIO_AUTH_TOKEN`/`HONEYPOT_PUBLIC_URL`, every webhook returns 403 rather
than accepting unauthenticated writes into the dataset.

## Classification

Both classifiers emit the same 16 labels (`honeypot/classify/rules.py:CATEGORIES`),
written to the same table keyed by classifier name — so the rule engine and
Claude can label the same call and be compared directly. The rule engine runs
inline on every transcription webhook so the dashboard is never empty; the
Claude pass runs as a batch job and updates its own row.

## Tests

```bash
python -m pytest tests -q
```

No test touches the network: the Claude classifier is exercised against a stub
client, and webhook tests sign their own requests.

## Scope

This repository does not contain, and will not contain, anything that posts
advertisements to sites the operator does not own. That is spam — it breaks
those sites' terms and the cost falls on their moderators and readers, not on
the scammers being studied. `honeypot/seeding/channels.py` rejects those channel
kinds by name. The supported alternatives are in `SEEDING.md`, and the fastest
one (`lead_form_optin`) generally produces traffic within a day.
