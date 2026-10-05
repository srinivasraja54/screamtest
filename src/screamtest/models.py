"""Typed records passed between pipeline stages.

Everything an LLM produces (EvidencePlan, Judgement) is a schema here, so it can
be validated before anything downstream trusts it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["active", "dead", "dormant_by_design", "unknown"]
Strength = Literal["hard", "soft"]


class Role(BaseModel):
    name: str
    arn: str
    created: datetime
    description: str = ""
    tags: dict[str, str] = Field(default_factory=dict)


class Evidence(BaseModel):
    collector: str
    strength: Strength
    summary: str
    location: str | None = None
    # Verbatim text lifted from the account or a repo. Data, never instructions.
    untrusted_text: str | None = None


# --- LLM outputs -----------------------------------------------------------
# Kept flat (no free-form dicts, no unions) so they map cleanly onto Gemini's
# and Claude's structured-output schemas.


class CollectorCall(BaseModel):
    collector: str
    window_days: int | None = None


class EvidencePlan(BaseModel):
    resource_class: Literal["aws_iam_role"]
    collectors: list[CollectorCall]
    rationale: str


class Judgement(BaseModel):
    verdict: Literal["dead", "dormant_by_design", "unknown"]
    reasoning: str
    cited_evidence: list[int] = Field(default_factory=list)


# --- Pipeline outputs ------------------------------------------------------


class Decision(BaseModel):
    role: str
    verdict: Verdict
    decided_by: Literal["rule", "llm", "gate", "backtest"]
    reasoning: str
    evidence: list[Evidence]
    llm_verdict: str | None = None


class BacktestResult(BaseModel):
    role: str
    window_days: int
    would_break: list[str]

    @property
    def passed(self) -> bool:
        return not self.would_break


class QuarantineAction(BaseModel):
    role: str
    apply: list[dict]
    undo: list[dict]
    dry_run: bool = True
