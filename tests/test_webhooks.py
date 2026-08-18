from honeypot.config import Config
from honeypot.telephony import twilio_webhooks as tw

URL = "https://honeypot.example/twilio/voice"
PARAMS = {"CallSid": "CA1", "From": "+15559990000", "To": "+15550001111"}


def test_a_correct_signature_validates():
    signature = tw.expected_signature("tok", URL, PARAMS)
    assert tw.signature_is_valid("tok", URL, PARAMS, signature)


def test_tampering_with_any_field_breaks_the_signature():
    signature = tw.expected_signature("tok", URL, PARAMS)
    assert not tw.signature_is_valid("tok", URL, {**PARAMS, "From": "+1"}, signature)
    assert not tw.signature_is_valid("tok", URL + "?x=1", PARAMS, signature)
    assert not tw.signature_is_valid("other", URL, PARAMS, signature)
    assert not tw.signature_is_valid("tok", URL, PARAMS, "")


def test_parameter_order_does_not_matter():
    reordered = dict(reversed(list(PARAMS.items())))
    assert tw.expected_signature("tok", URL, PARAMS) == tw.expected_signature(
        "tok", URL, reordered
    )


def test_recording_notice_precedes_the_recorder():
    xml = tw.voice_response(Config(record_calls=True, public_base_url="https://h.example"))
    assert xml.index("recorded") < xml.index("<Record")
    assert 'transcribe="true"' in xml


def test_without_recording_no_recorder_is_emitted():
    xml = tw.voice_response(Config(record_calls=False))
    assert "<Record" not in xml
    assert "<Say" in xml


def test_markup_in_the_notice_is_escaped():
    xml = tw.voice_response(
        Config(record_calls=True, recording_notice='</Say><Dial>+1900</Dial><Say>')
    )
    assert "<Dial>" not in xml
    assert "&lt;Dial&gt;" in xml


def test_sms_reply_is_silent_by_default():
    assert "<Message>" not in tw.sms_response()
    assert "<Message>hi</Message>" in tw.sms_response("hi")
