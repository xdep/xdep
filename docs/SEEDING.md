# Seeding the honeypot

The number has to get in front of fraud operations somehow. Each supported route
is one the operator either owns or is invited into, and each gets its own DID so
inbound traffic names its own source.

Run `python -m honeypot kinds` for the same list from the command line.

## Channels, fastest first

### `lead_form_optin` — hours to days
Enter your own honeypot number into quote and offer forms that resell leads:
auto insurance, home warranty, solar, debt consolidation, "check if you qualify"
pages. You are consenting on your own behalf, for your own line, which is the
one thing that makes this different from every route on the rejected list. These
lists are the direct feedstock for the call centres you want to measure, so this
is normally the highest-yield channel by a wide margin.

Use a distinct DID per vertical if you want to know which industry sells the
list on hardest.

### `inbound_reply` — minutes to hours
Give the number out only in reply to something that contacted you first: a scam
text, a robocall callback number, a phishing email. Responding to someone who
opened the conversation is not solicitation, and it reaches the operator
directly rather than going through a list broker. This is also the channel that
gets you live humans rather than recordings.

### `reporting_feed` — days
Carriers, regulators, and academic robocall projects run honeypot exchanges and
accept contributed numbers. Traffic arrives already correlated with data those
programmes hold, which makes your own numbers far more interpretable.

### `owned_web` — days to weeks
A contact page on a domain you own. `python -m honeypot site` generates one per
registered `owned_web` channel with the number in the text, in a `tel:` link, and
in schema.org microdata, plus a `robots.txt` that invites crawlers instead of
blocking them — harvesting bots pick these up the same way they pick up any
contact page.

```bash
python -m honeypot site --out ./public --base-url https://example.org \
    --email contact@example.org --site-name "Contact"
```

The generated pages never impersonate a real company and carry a visible
monitoring notice. Keep it that way: the notice is what you point at afterwards.

### `owned_profile` — weeks
The number in the contact field of an account you legitimately hold. Publishing
your own contact detail on your own profile is within any platform's terms.
Bulk-posting content to that platform is not — that is the line.

### `printed` — weeks to months
Signage, cards, a vehicle decal. Slow, but it catches locally-sourced fraud that
never touches an online list.

### `direct_share` — control line
Given only to a named collaborator. This line should stay silent, so anything
that arrives on it tells you a partner's list leaked. Register one even if you
never expect traffic; a control channel is what turns the other numbers from
anecdote into measurement.

## Measuring

```bash
python -m honeypot channels
```

Per channel: calls, distinct callers, and `hours_to_first_call` — how long the
number sat published before anything dialled it. Latency is usually the more
interesting figure; volume tells you how hard a list is being resold, latency
tells you how fast it got there.

Keep at least one channel idle for a fortnight before seeding it, so you have a
baseline for whatever background scanning traffic the number range already
attracts.

## Not supported

Posting ads or listings to sites you do not own — classifieds, forums,
marketplaces, comment sections — is not a channel here, and
`honeypot/seeding/channels.py` rejects those kinds by name.

It is spam. It breaks those sites' terms, and the cost lands on their moderators
and on the people who answer the listing in good faith, not on the scammers. It
also corrupts the measurement: a number smeared across a hundred scraped pages
cannot tell you which channel produced which call, which is the question the
platform exists to answer.

`lead_form_optin` reaches the same call centres faster, with attribution intact.
