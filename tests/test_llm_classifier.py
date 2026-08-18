"""The Claude classifier is exercised against a stub client — no network."""

import json
from types import SimpleNamespace

import pytest

from honeypot import db
from honeypot.classify import llm, pipeline
from honeypot.config import Config


class StubClient:
    """Mimics the slice of the SDK surface ``llm.classify`` touches."""

    def __init__(self, payload=None, *, stop_reason="end_turn", error=None):
        self.payload = payload
        self.stop_reason = stop_reason
        self.error = error
        self.calls = []

        outer = self

        class Messages:
            def create(self, **kwargs):
                outer.calls.append(kwargs)
                if outer.error:
                    raise outer.error
                text = json.dumps(outer.payload) if outer.payload is not None else "{}"
                return SimpleNamespace(
                    stop_reason=outer.stop_reason,
                    content=[SimpleNamespace(type="text", text=text)],
                )

        self.beta = SimpleNamespace(messages=Messages())


PAYLOAD = {
    "category": "tech_support",
    "confidence": 0.91,
    "indicators": ["install AnyDesk"],
    "summary": "Caller claimed to be Microsoft support and asked for remote access.",
}


def test_a_structured_response_is_parsed_into_a_result():
    result = llm.classify("your computer is infected", client=StubClient(PAYLOAD))
    assert result.category == "tech_support"
    assert result.confidence == pytest.approx(0.91)
    assert result.indicators == ["install AnyDesk"]
    assert result.classifier == llm.MODEL


def test_the_request_pins_the_model_and_constrains_the_labels():
    client = StubClient(PAYLOAD)
    llm.classify("hello", client=client)
    request = client.calls[0]
    assert request["model"] == "claude-opus-5"
    schema = request["output_config"]["format"]["schema"]
    assert schema["properties"]["category"]["enum"] == list(llm.CATEGORIES)
    assert schema["additionalProperties"] is False


def test_a_refusal_falls_back_to_the_rule_engine():
    client = StubClient(PAYLOAD, stop_reason="refusal")
    result = llm.classify(
        "This is the IRS and there is an arrest warrant filed against you.",
        client=client,
    )
    assert result.category == "government_impersonation"
    assert "rules" in result.classifier


def test_a_failed_request_does_not_strand_the_rest_of_the_batch(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.sqlite3"), use_llm_classifier=True)
    client = StubClient(error=RuntimeError("boom"))
    with db.session(cfg.db_path) as conn:
        for index, text in enumerate(
            [
                "This is the IRS, an arrest warrant has been filed against you.",
                "Final notice about your car's extended vehicle warranty.",
            ]
        ):
            call = db.record_call_start(conn, f"CA{index}", "+1555", "+1555", None)
            db.add_transcript(conn, call, text, "test")

        # Force the pipeline onto the stub instead of a real client.
        original = llm._client
        llm._client = lambda: client
        try:
            report = pipeline.run(conn, cfg)
        finally:
            llm._client = original

        assert report.classified == 2
        categories = {row["category"] for row in db.stats(conn)["by_category"]}
        assert categories == {"government_impersonation", "auto_warranty"}


def test_pipeline_degrades_cleanly_when_no_credentials_exist(tmp_path):
    cfg = Config(db_path=str(tmp_path / "t.sqlite3"), use_llm_classifier=True)
    original = llm._client

    def unavailable():
        raise llm.ClassifierUnavailable("no api key")

    llm._client = unavailable
    try:
        with db.session(cfg.db_path) as conn:
            call = db.record_call_start(conn, "CA1", "+1555", "+1555", None)
            db.add_transcript(conn, call, "Your vehicle warranty is expiring soon now.", "t")
            report = pipeline.run(conn, cfg)
    finally:
        llm._client = original

    assert report.classifier == "rules/v1"
    assert "no api key" in (report.degraded_reason or "")
    assert report.classified == 1
