"""Twilio webhook helpers: request authentication and TwiML generation.

Kept free of any web framework so the logic can be unit-tested directly and
reused if the provider ever changes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from urllib.parse import urlencode
from xml.sax.saxutils import escape, quoteattr

from ..config import Config


def expected_signature(auth_token: str, url: str, params: dict[str, str]) -> str:
    """Recompute Twilio's ``X-Twilio-Signature`` for a form-encoded POST.

    Twilio concatenates the full request URL with every POST parameter sorted by
    key (key immediately followed by value, no separators), then HMAC-SHA1s that
    with the account auth token.
    """
    payload = url + "".join(f"{k}{params[k]}" for k in sorted(params))
    digest = hmac.new(
        auth_token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha1
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def signature_is_valid(
    auth_token: str, url: str, params: dict[str, str], signature: str
) -> bool:
    return hmac.compare_digest(
        expected_signature(auth_token, url, params), signature or ""
    )


def _say(text: str, *, voice: str = "Polly.Joanna") -> str:
    return f"<Say voice={quoteattr(voice)}>{escape(text)}</Say>"


def voice_response(cfg: Config, *, action_path: str = "/twilio/recording") -> str:
    """TwiML for an inbound call.

    When recording is enabled the caller hears the disclosure *before* anything
    is captured — that ordering is the whole point of the notice, so it is not
    configurable. When recording is off the line still answers and holds, which
    is enough to log the call and let the caller reveal themselves over SMS.
    """
    parts: list[str] = []
    callback = f"{cfg.public_base_url}{action_path}" if cfg.public_base_url else action_path

    if cfg.record_calls:
        parts.append(_say(cfg.recording_notice))
        parts.append("<Pause length=\"1\"/>")
        parts.append(_say("Hello? Yes, speaking. How can I help you?"))
        parts.append(
            "<Record "
            f"action={quoteattr(callback)} "
            f"recordingStatusCallback={quoteattr(callback)} "
            "method=\"POST\" maxLength=\"600\" playBeep=\"false\" "
            "trim=\"trim-silence\" transcribe=\"true\" "
            f"transcribeCallback={quoteattr(callback + '/transcription')}/>"
        )
    else:
        parts.append(_say("Hello? Hello, who is this please?"))
        parts.append("<Pause length=\"20\"/>")
        parts.append(_say("Sorry, I can't hear you. Goodbye."))

    return f"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response>{''.join(parts)}</Response>"


def sms_response(reply: str | None = None) -> str:
    """TwiML for an inbound SMS.

    The default is an empty response: the message is logged and nothing is sent
    back. Auto-replying to an unknown sender confirms the line is live and costs
    money on every junk message.
    """
    body = f"<Message>{escape(reply)}</Message>" if reply else ""
    return f"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response>{body}</Response>"


def form_url(base: str, path: str, query: dict[str, str] | None = None) -> str:
    url = f"{base.rstrip('/')}{path}"
    if query:
        url = f"{url}?{urlencode(query)}"
    return url
