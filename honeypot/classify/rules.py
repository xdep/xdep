"""Keyword-and-weight classifier for call transcripts and SMS bodies.

This is the offline baseline: no API key, no network, deterministic. It exists
for two reasons — it labels the corpus when the LLM classifier is unavailable,
and it gives the LLM classifier something to be measured against.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Canonical label set. The LLM classifier is constrained to these same values
#: so both classifiers land in one comparable column.
CATEGORIES: tuple[str, ...] = (
    "government_impersonation",
    "tech_support",
    "auto_warranty",
    "debt_or_loan",
    "utility_disconnect",
    "delivery_phish",
    "bank_or_payment_fraud",
    "crypto_investment",
    "prize_or_lottery",
    "insurance_or_medical",
    "job_offer",
    "romance_or_relationship",
    "charity",
    "robocall_probe",
    "legitimate",
    "unknown",
)

# Each phrase carries a weight. Phrases that only a scammer would string
# together score higher than individually common words.
_SIGNALS: dict[str, list[tuple[str, float]]] = {
    "government_impersonation": [
        (r"\b(irs|internal revenue)\b", 3.0),
        (r"\bsocial security (number|administration)\b", 3.0),
        (r"\barrest warrant\b", 3.5),
        (r"\b(federal|legal) (case|action) (against|filed)\b", 2.5),
        (r"\bimmigration\b", 1.5),
        (r"\bback taxes\b", 2.5),
        (r"\bsuspend(ed)? your (social security|benefits)\b", 3.0),
    ],
    "tech_support": [
        (r"\b(microsoft|windows|apple) (support|security|technician)\b", 3.5),
        (r"\byour computer (is|has been) (infected|compromised|hacked)\b", 3.5),
        (r"\bremote (access|desktop|session)\b", 2.0),
        (r"\banydesk|teamviewer|ultraviewer\b", 3.0),
        (r"\bvirus (detected|alert)\b", 2.5),
        (r"\bsubscription (renewal|auto-?renew)\b", 1.5),
        (r"\b(geek squad|norton|mcafee)\b", 2.5),
    ],
    "auto_warranty": [
        (r"\b(vehicle|auto|car) (service )?warranty\b", 4.0),
        (r"\bextend(ed|ing)? (your )?(factory )?warranty\b", 3.5),
        (r"\bfinal notice about your (car|vehicle)\b", 3.5),
        (r"\bbumper.to.bumper\b", 2.5),
    ],
    "debt_or_loan": [
        (r"\bdebt (relief|consolidation|forgiveness)\b", 3.5),
        (r"\bstudent loan (forgiveness|relief)\b", 3.5),
        (r"\bpre.?approved\b", 2.0),
        (r"\blower your interest rate\b", 3.0),
        (r"\bcredit card (debt|rate)\b", 2.0),
    ],
    "utility_disconnect": [
        (r"\b(power|electric|gas|water) (will be )?(shut ?off|disconnect)", 3.5),
        (r"\bpast due (balance|bill)\b", 2.0),
        (r"\bwithin (30|thirty|45|forty.five) minutes\b", 2.5),
    ],
    "delivery_phish": [
        (r"\b(usps|ups|fedex|dhl)\b", 2.5),
        (r"\b(package|parcel|shipment) (could not|couldn.t|failed to) be deliver", 3.5),
        (r"\bdelivery (attempt|address) (failed|issue|problem)\b", 3.0),
        (r"\btracking (number|link)\b", 1.5),
    ],
    "bank_or_payment_fraud": [
        (r"\b(suspicious|unauthorized|fraudulent) (charge|transaction|activity)\b", 3.5),
        (r"\b(zelle|venmo|cash ?app|wire transfer)\b", 2.5),
        (r"\byour (account|card) (has been )?(locked|frozen|suspended)\b", 3.0),
        (r"\bverify your (identity|account|pin)\b", 2.5),
        (r"\bone.?time (code|password|passcode)\b", 3.0),
        (r"\bsecurity department\b", 2.0),
    ],
    "crypto_investment": [
        (r"\b(bitcoin|crypto|usdt|ethereum)\b", 2.5),
        (r"\b(guaranteed|risk.?free) (return|profit)\b", 3.5),
        (r"\btrading (platform|signal|group)\b", 2.5),
        (r"\bdouble your (money|investment)\b", 3.5),
    ],
    "prize_or_lottery": [
        (r"\byou(.ve| have) (won|been selected)\b", 3.5),
        (r"\b(grand )?prize\b", 2.0),
        (r"\b(sweepstakes|lottery|publishers clearing)\b", 3.0),
        (r"\bclaim your (prize|reward|winnings)\b", 3.5),
        (r"\b(processing|delivery) fee\b", 2.5),
    ],
    "insurance_or_medical": [
        (r"\b(health|medical|dental) (insurance|plan|coverage)\b", 2.5),
        (r"\bmedicare\b", 3.0),
        (r"\b(back|knee|orthopedic) brace\b", 3.5),
        (r"\bopen enrollment\b", 2.0),
    ],
    "job_offer": [
        (r"\b(work from home|remote position)\b", 2.5),
        (r"\b(daily|weekly) (pay|salary) of\b", 3.0),
        (r"\bpart.?time (job|role|task)\b", 2.0),
        (r"\b(whatsapp|telegram) (me|us|for details)\b", 3.0),
    ],
    "romance_or_relationship": [
        (r"\bis this (still )?(john|mike|sarah|lisa|david)\b", 2.5),
        (r"\bsorry,? wrong number\b", 3.0),
        (r"\bnice to meet you\b", 1.5),
        (r"\b(lonely|my dear|handsome|beautiful)\b", 2.0),
    ],
    "charity": [
        (r"\bdonation\b", 2.0),
        (r"\b(police|firefighter|veterans?) (fund|association|charity)\b", 3.0),
        (r"\btax.deductible\b", 1.5),
    ],
}

_URGENCY = [
    (r"\bimmediately\b", 1.0),
    (r"\bdo not hang up\b", 2.0),
    (r"\bpress (one|1|two|2)\b", 1.5),
    (r"\bfinal (notice|warning|attempt)\b", 1.5),
    (r"\bgift ?card\b", 2.5),
    (r"\bdo not tell (anyone|the bank)\b", 2.5),
]

# Under this many characters a transcript is a hangup or dead air, not speech.
_MIN_SPEECH_CHARS = 25


@dataclass(frozen=True)
class Result:
    category: str
    confidence: float
    indicators: list[str]
    summary: str | None = None
    classifier: str = "rules/v1"


def _score(text: str) -> dict[str, tuple[float, list[str]]]:
    scores: dict[str, tuple[float, list[str]]] = {}
    for category, signals in _SIGNALS.items():
        total = 0.0
        hits: list[str] = []
        for pattern, weight in signals:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                total += weight
                hits.append(match.group(0).strip().lower())
        if total:
            scores[category] = (total, hits)
    return scores


def classify(text: str) -> Result:
    """Label one transcript or message body."""
    cleaned = (text or "").strip()
    if len(cleaned) < _MIN_SPEECH_CHARS:
        return Result("robocall_probe", 0.4, [], "No usable speech captured.")

    scores = _score(cleaned)
    if not scores:
        return Result("unknown", 0.2, [])

    urgency_hits = [
        m.group(0).strip().lower()
        for m in (re.search(p, cleaned, re.IGNORECASE) for p, _ in _URGENCY)
        if m
    ]
    urgency = sum(w for p, w in _URGENCY if re.search(p, cleaned, re.IGNORECASE))

    category, (top, hits) = max(scores.items(), key=lambda kv: kv[1][0])
    runner_up = max(
        (v[0] for k, v in scores.items() if k != category), default=0.0
    )

    # Confidence rises with the winner's score, with how far it beats the
    # runner-up, and with pressure tactics that mark a call as a scam at all.
    margin = top - runner_up
    raw = 0.35 + 0.09 * top + 0.06 * margin + 0.03 * urgency
    confidence = round(min(raw, 0.95), 2)
    return Result(category, confidence, hits + urgency_hits)
