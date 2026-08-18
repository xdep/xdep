# Legal and ethical constraints

Not legal advice. This file records the constraints the code is built around and
the decisions left to the operator. Rules differ by jurisdiction — take advice
before recording anything.

## Call recording consent

`HONEYPOT_RECORD_CALLS` defaults to **off**. Recording is the most legally
loaded thing this platform does.

- **All-party consent jurisdictions.** Several US states (California, Florida,
  Illinois, Maryland, Massachusetts, Montana, Nevada, New Hampshire,
  Pennsylvania, Washington, and others) require every party to consent, and many
  countries outside the US are stricter still. The relevant law generally follows
  where the *parties* are, not where the server is — and an inbound scam call can
  originate anywhere.
- **The notice is not optional and not reorderable.** When recording is enabled,
  `voice_response()` plays `HONEYPOT_RECORDING_NOTICE` before `<Record>` starts.
  A test asserts that ordering. Do not restructure the TwiML to capture audio
  first.
- **Wrong numbers get recorded too.** Not everyone who dials a honeypot is a
  scammer. Someone will misdial, and a real person's voice will land in the
  dataset. Set a retention window and actually enforce it.

## Outbound calling

This platform never places calls. It answers them. Automated outbound dialling
brings the TCPA and its equivalents into scope, with statutory damages per call,
and none of this code should be repurposed for it.

## The advertisements

The platform seeds its number through channels the operator controls or is
invited into (`SEEDING.md`). It deliberately cannot post advertisements to
third-party sites:

- Automated posting breaks essentially every such site's terms of service, and in
  some jurisdictions unauthorised automated use of a computer system is more than
  a contract problem.
- The harm falls on the platform's moderators and on readers who answer a listing
  in good faith — not on the fraud operations being studied.
- A generated page must never impersonate a real business. `landing.py` writes
  the operator's own listing with a visible monitoring notice.

## Data handling

- **Recordings and transcripts are personal data.** Under GDPR/UK GDPR a caller's
  voice and number are personal data even when the caller is committing fraud.
  Research use needs a lawful basis, a retention limit, and a deletion path.
- **Third-party details leak into transcripts.** Scammers name real banks, real
  people, and sometimes real victims. Treat the transcript store as sensitive.
- **Do not publish raw caller numbers.** Aggregate before sharing. Numbers are
  routinely spoofed, so a published "scammer number" is usually some uninvolved
  person's line.
- **Retention.** Nothing here expires records automatically. Decide the window,
  write the cron job, and document it here before the first real call lands.

## Provider terms

Twilio's acceptable use policy governs how the numbers may be used. Honeypot
research is ordinarily fine; using the same account to place bulk outbound calls
or to send unsolicited SMS is not, and it will take the numbers down.

## Engagement

Logging inbound calls is passive. Actively engaging a caller — stringing them
along, feeding them fabricated bank details, running a bot that wastes their time
— is a different activity with a different risk profile, and this platform does
not do it. If you add it, get advice first.
