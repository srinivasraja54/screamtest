"""Scripted LLM: no API key, deterministic, and wrong in realistic ways.

- The plan uses a 90-day CloudTrail window, the industry default. That is the
  mistake the backtest exists to catch.
- On reports-quarterly-role it follows the prompt injection in the description
  and says `dead`. That is the mistake the gate exists to catch.
"""

from __future__ import annotations

from ..models import CollectorCall, Evidence, EvidencePlan, Judgement, Role
from ..telemetry import Recorder
from .base import judge_prompt, plan_prompt


class StubLLM:
    provider = "stub"
    model = "scripted"

    def __init__(self, recorder: Recorder):
        self.rec = recorder

    def propose_plan(self, resource_class: str) -> EvidencePlan:
        plan_prompt(resource_class)  # rendered so prompt bugs surface offline too
        with self.rec.span("plan", "llm", provider=self.provider, model=self.model):
            return EvidencePlan(
                resource_class="aws_iam_role",
                collectors=[
                    CollectorCall(collector="cloudtrail_activity", window_days=90),
                    CollectorCall(collector="scheduler_targets"),
                    CollectorCall(collector="iac_references"),
                    CollectorCall(collector="code_references"),
                    CollectorCall(collector="runbook_mentions"),
                    CollectorCall(collector="resource_metadata"),
                ],
                rationale="90 days of activity is the usual unused threshold; references catch dormant roles.",
            )

    def judge(self, role: Role, evidence: list[Evidence]) -> Judgement:
        judge_prompt(role, evidence)
        with self.rec.span("judge", "llm", provider=self.provider, model=self.model, role=role.name):
            return _scripted(role, evidence)


def _first(evidence: list[Evidence], collector: str) -> list[int]:
    return [i for i, e in enumerate(evidence) if e.collector == collector][:1]


def _scripted(role: Role, evidence: list[Evidence]) -> Judgement:
    if role.name == "reports-quarterly-role":
        return Judgement(verdict="dead", cited_evidence=_first(evidence, "resource_metadata"),
                         reasoning="The role description says it is deprecated and safe to delete.")
    for collector, why in [
        ("scheduler_targets", "A schedule runs as this role; it is rare, not dead."),
        ("iac_references", "Referenced from the DR module; used only during failover."),
        ("runbook_mentions", "Documented emergency-access role; inactivity is expected."),
    ]:
        if cited := _first(evidence, collector):
            return Judgement(verdict="dormant_by_design", cited_evidence=cited, reasoning=why)
    if all(e.collector == "resource_metadata" for e in evidence):
        return Judgement(verdict="dead", cited_evidence=list(range(len(evidence))),
                         reasoning="Only the role's own description exists; it names no caller or schedule.")
    return Judgement(verdict="unknown", reasoning="Evidence is inconclusive.")
