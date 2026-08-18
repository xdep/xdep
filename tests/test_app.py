import pytest
from fastapi.testclient import TestClient

from honeypot import app as app_module
from honeypot import db
from honeypot.config import Config
from honeypot.seeding import channels
from honeypot.telephony import twilio_webhooks as tw

TOKEN = "test-auth-token"
BASE = "http://testserver"


@pytest.fixture()
def cfg(tmp_path):
    return Config(
        db_path=str(tmp_path / "t.sqlite3"),
        twilio_auth_token=TOKEN,
        public_base_url=BASE,
        verify_signatures=True,
        record_calls=True,
    )


@pytest.fixture()
def client(cfg):
    app_module.app.dependency_overrides[app_module.get_config] = lambda: cfg
    with db.session(cfg.db_path) as conn:
        channels.register(conn, "site", "Contact page", "owned_web", "+15550001111")
    with TestClient(app_module.app) as test_client:
        yield test_client
    app_module.app.dependency_overrides.clear()


def post(client, path, form):
    signature = tw.expected_signature(TOKEN, f"{BASE}{path}", form)
    return client.post(path, data=form, headers={"X-Twilio-Signature": signature})


def test_unsigned_webhooks_are_rejected(client):
    response = client.post(
        "/twilio/voice", data={"CallSid": "CA1", "From": "+1555", "To": "+1555"}
    )
    assert response.status_code == 403


def test_a_signed_call_is_logged_and_attributed(client, cfg):
    response = post(
        client,
        "/twilio/voice",
        {"CallSid": "CA1", "From": "+15559990000", "To": "+15550001111"},
    )
    assert response.status_code == 200
    assert "<Record" in response.text

    stats = client.get("/api/stats").json()
    assert stats["total_calls"] == 1
    assert stats["by_channel"][0]["channel"] == "site"


def test_transcription_is_stored_and_labelled(client):
    post(client, "/twilio/voice", {"CallSid": "CA1", "From": "+1555", "To": "+15550001111"})
    post(
        client,
        "/twilio/recording/transcription",
        {
            "CallSid": "CA1",
            "TranscriptionText": "This is the IRS, there is an arrest warrant against you.",
        },
    )
    call = client.get("/api/calls").json()[0]
    assert call["category"] == "government_impersonation"
    assert "IRS" in call["transcript"]


def test_transcription_for_an_unknown_call_is_a_404(client):
    response = post(
        client, "/twilio/recording/transcription",
        {"CallSid": "NOPE", "TranscriptionText": "hello"},
    )
    assert response.status_code == 404


def test_inbound_sms_is_logged_without_replying(client):
    response = post(
        client,
        "/twilio/sms",
        {
            "MessageSid": "SM1",
            "From": "+15559990000",
            "To": "+15550001111",
            "Body": "Your package could not be delivered, confirm your USPS address.",
        },
    )
    assert response.status_code == 200
    assert "<Message>" not in response.text
    assert client.get("/api/stats").json()["total_messages"] == 1


def test_call_status_records_duration(client):
    post(client, "/twilio/voice", {"CallSid": "CA1", "From": "+1555", "To": "+15550001111"})
    post(client, "/twilio/status", {"CallSid": "CA1", "CallStatus": "completed", "CallDuration": "73"})
    assert client.get("/api/calls").json()[0]["duration_s"] == 73


def test_dashboard_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Inbound activity" in response.text


def test_verification_cannot_be_bypassed_by_omitting_the_token(tmp_path):
    """A missing auth token must fail closed, not wave requests through."""
    broken = Config(db_path=str(tmp_path / "t.sqlite3"), twilio_auth_token=None,
                    public_base_url=BASE, verify_signatures=True)
    app_module.app.dependency_overrides[app_module.get_config] = lambda: broken
    with TestClient(app_module.app) as test_client:
        response = test_client.post(
            "/twilio/voice", data={"CallSid": "CA1", "From": "+1", "To": "+1"}
        )
    app_module.app.dependency_overrides.clear()
    assert response.status_code == 403
