"""Runtime configuration, read from the environment.

Nothing here has a secret baked in. Everything the platform needs to talk to a
telephony provider or to the Claude API comes from env vars so the same tree can
run locally, in CI, and on a box that answers real calls.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    # Where call/SMS records live. SQLite keeps the whole thing single-file.
    db_path: str = field(
        default_factory=lambda: os.environ.get("HONEYPOT_DB", "honeypot.sqlite3")
    )

    # Twilio validates its webhooks by signing them with the account auth token.
    # Without a token we refuse to run in signature-checking mode (see app.py).
    twilio_auth_token: str | None = field(
        default_factory=lambda: os.environ.get("TWILIO_AUTH_TOKEN")
    )
    verify_signatures: bool = field(
        default_factory=lambda: _env_bool("HONEYPOT_VERIFY_SIGNATURES", True)
    )
    # Public base URL of this service, as the provider sees it. Signature
    # validation hashes the full URL, so a proxy that rewrites the host has to be
    # accounted for here.
    public_base_url: str = field(
        default_factory=lambda: os.environ.get("HONEYPOT_PUBLIC_URL", "").rstrip("/")
    )

    # Recording is the single most legally loaded thing this platform does.
    # Both switches default to the conservative setting.
    record_calls: bool = field(
        default_factory=lambda: _env_bool("HONEYPOT_RECORD_CALLS", False)
    )
    recording_notice: str = field(
        default_factory=lambda: os.environ.get(
            "HONEYPOT_RECORDING_NOTICE",
            "This call may be recorded and monitored for security research.",
        )
    )

    # Claude-backed transcript classification. Falls back to the rule engine when
    # no key is resolvable.
    classifier_model: str = field(
        default_factory=lambda: os.environ.get("HONEYPOT_MODEL", "claude-opus-5")
    )
    use_llm_classifier: bool = field(
        default_factory=lambda: _env_bool("HONEYPOT_USE_LLM", True)
    )

    @property
    def can_verify_signatures(self) -> bool:
        return bool(self.twilio_auth_token) and bool(self.public_base_url)


def load() -> Config:
    return Config()
