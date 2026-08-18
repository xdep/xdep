"""Batch classification of stored transcripts."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .. import db
from ..config import Config
from . import llm, rules


@dataclass
class RunReport:
    classified: int = 0
    skipped: int = 0
    classifier: str = rules.Result.classifier
    degraded_reason: str | None = None

    def __str__(self) -> str:
        line = f"classified {self.classified} call(s) with {self.classifier}"
        if self.degraded_reason:
            line += f" (fell back to rules: {self.degraded_reason})"
        return line


def run(conn: sqlite3.Connection, cfg: Config) -> RunReport:
    """Label every transcript that this classifier has not seen yet.

    Falls back to the rule engine as a whole run if Claude is unreachable, and
    per-transcript if a single request fails, so one bad call never strands the
    rest of the backlog.
    """
    report = RunReport()
    client = None

    if cfg.use_llm_classifier:
        try:
            client = llm._client()
            report.classifier = cfg.classifier_model
        except llm.ClassifierUnavailable as exc:
            report.degraded_reason = str(exc)
    else:
        report.degraded_reason = "HONEYPOT_USE_LLM is off"

    pending = db.unclassified_calls(conn, report.classifier)
    for row in pending:
        if client is not None:
            try:
                result = llm.classify(
                    row["text"], model=cfg.classifier_model, client=client
                )
            except Exception as exc:  # noqa: BLE001 - keep the batch moving
                result = rules.classify(row["text"])
                result = rules.Result(
                    result.category,
                    result.confidence,
                    result.indicators,
                    f"Claude request failed ({exc.__class__.__name__}); rule result shown.",
                    classifier=report.classifier,
                )
        else:
            result = rules.classify(row["text"])
            result = rules.Result(
                result.category,
                result.confidence,
                result.indicators,
                result.summary,
                classifier=report.classifier,
            )

        db.save_classification(
            conn,
            "call",
            int(row["call_id"]),
            result.category,
            result.confidence,
            result.indicators,
            result.summary,
            report.classifier,
        )
        report.classified += 1

    return report
