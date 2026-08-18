"""Claude-backed transcript classification.

The rule engine in ``rules.py`` catches the boilerplate robocall scripts. This
classifier handles the rest: live human callers who improvise, transcripts that
speech-to-text mangled, and social-engineering that has no fixed keywords.

Output is constrained to the same label set the rule engine uses, so both
classifiers write into the same column and can be compared directly.
"""

from __future__ import annotations

import json
from typing import Any

from .rules import CATEGORIES, Result
from .rules import classify as classify_with_rules

MODEL = "claude-opus-5"

SYSTEM = """You label transcripts of inbound phone calls and text messages \
received by a security-research honeypot line. The line is never used to place \
outbound calls and is not a real customer's number, so every inbound contact is \
either unsolicited or a wrong number.

Label what the caller is actually attempting. Judge from the content of the \
transcript alone. Speech-to-text output is noisy: expect dropped words, wrong \
homophones, and mangled proper nouns, and do not lower confidence purely \
because the text is garbled. If the transcript carries no real speech (dead \
air, hold music, a beep and a hangup), use robocall_probe. If the caller \
appears to have genuinely misdialed or is a real business the line's owner \
deals with, use legitimate. Use unknown only when the content is readable but \
its intent genuinely is not."""

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "category": {"type": "string", "enum": list(CATEGORIES)},
        "confidence": {
            "type": "number",
            "description": "0.0-1.0 likelihood the category is correct.",
        },
        "indicators": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Short verbatim phrases from the transcript that drove the label.",
        },
        "summary": {
            "type": "string",
            "description": "One sentence: what the caller wanted and what they asked the callee to do.",
        },
    },
    "required": ["category", "confidence", "indicators", "summary"],
    "additionalProperties": False,
}


class ClassifierUnavailable(RuntimeError):
    """Raised when no usable Claude client could be constructed."""


def _client() -> Any:
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover - depends on install extras
        raise ClassifierUnavailable("anthropic SDK is not installed") from exc
    try:
        return anthropic.Anthropic()
    except Exception as exc:  # noqa: BLE001 - SDK raises on missing credentials
        raise ClassifierUnavailable(str(exc)) from exc


def classify(text: str, *, model: str = MODEL, client: Any | None = None) -> Result:
    """Label one transcript with Claude, falling back to rules on refusal."""
    api = client or _client()
    response = api.beta.messages.create(
        model=model,
        max_tokens=2000,
        system=SYSTEM,
        # Server-side fallbacks: if a safety classifier declines the request,
        # the API reroutes rather than handing back an empty turn.
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        output_config={
            # Labelling is a shallow task; low effort keeps per-call cost down
            # without disabling thinking, which Opus 5 handles poorly.
            "effort": "low",
            "format": {"type": "json_schema", "schema": _SCHEMA},
        },
        messages=[
            {
                "role": "user",
                "content": f"<transcript>\n{text.strip()}\n</transcript>",
            }
        ],
    )

    if getattr(response, "stop_reason", None) == "refusal":
        fallback = classify_with_rules(text)
        return Result(
            fallback.category,
            fallback.confidence,
            fallback.indicators,
            "Model declined to label this transcript; rule engine result shown.",
            classifier=f"{model}/refused->rules",
        )

    payload = next(b.text for b in response.content if b.type == "text")
    data = json.loads(payload)
    return Result(
        category=data["category"],
        confidence=float(data["confidence"]),
        indicators=list(data["indicators"]),
        summary=data["summary"],
        classifier=model,
    )
