"""Deterministic triage, the gate over LLM judgements, and the backtest.

The LLM only sees the ambiguous middle. Clear cases are decided by rules, and
nothing the LLM says can push a role with hard evidence to `dead`.
"""

from __future__ import annotations

from .collectors import MAX_RETENTION_DAYS
from .models import BacktestResult, Decision, Evidence, Judgement, Role
from .sandbox import Sandbox


def triage(role: Role, evidence: list[Evidence]) -> Decision | None:
    """Decide the clear cases. Returns None when the LLM must judge."""
    if any(e.collector == "cloudtrail_activity" for e in evidence):
        return Decision(role=role.name, verdict="active", decided_by="rule",
                        reasoning="Recent API activity inside the plan window.", evidence=evidence)
    if not evidence:
        return Decision(role=role.name, verdict="dead", decided_by="rule",
                        reasoning="No activity in window and no references anywhere.", evidence=evidence)
    return None


def gate(role: Role, evidence: list[Evidence], j: Judgement) -> Decision:
    """Accept the LLM's judgement only where the evidence allows it."""
    hard = [e for e in evidence if e.strength == "hard"]
    if j.verdict == "dead" and hard:
        return Decision(
            role=role.name, verdict="unknown", decided_by="gate", llm_verdict=j.verdict, evidence=evidence,
            reasoning=f"LLM said dead, but {len(hard)} hard reference(s) exist ({hard[0].location}). Overridden.",
        )
    bad = [i for i in j.cited_evidence if not 0 <= i < len(evidence)]
    if j.verdict == "dormant_by_design" and (not j.cited_evidence or bad):
        return Decision(
            role=role.name, verdict="unknown", decided_by="gate", llm_verdict=j.verdict, evidence=evidence,
            reasoning="LLM claimed dormant-by-design without citing valid evidence.",
        )
    return Decision(role=role.name, verdict=j.verdict, decided_by="llm", llm_verdict=j.verdict,
                    reasoning=j.reasoning, evidence=evidence)


def backtest(sb: Sandbox, role: Role) -> BacktestResult:
    """Would denying this role have broken anything, over full retention?

    The window is fixed here, not taken from the plan: the check that guards a
    destructive action must not be tunable by the model whose output it checks.
    """
    events = sb.events_for(role.arn, MAX_RETENTION_DAYS)
    return BacktestResult(
        role=role.name,
        window_days=MAX_RETENTION_DAYS,
        would_break=[f"{e.time:%Y-%m-%d} {e.source}:{e.name} ({e.event_id})" for e in events],
    )
