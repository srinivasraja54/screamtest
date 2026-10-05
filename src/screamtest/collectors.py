"""Deterministic evidence collectors, and the compiler that admits a plan.

The LLM chooses *which* collectors to run and with what parameters. It cannot add
a collector, and every parameter is bounds-checked here. A plan that names
anything outside this registry is rejected, not repaired.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .models import Evidence, EvidencePlan, Role
from .sandbox import Sandbox

MAX_RETENTION_DAYS = 365


@dataclass(frozen=True)
class Spec:
    fn: Callable[..., list[Evidence]]
    doc: str
    takes_window: bool = False


def cloudtrail_activity(sb: Sandbox, role: Role, window_days: int) -> list[Evidence]:
    events = sb.events_for(role.arn, window_days)
    if not events:
        return []
    last = events[0]
    return [
        Evidence(
            collector="cloudtrail_activity",
            strength="hard",
            summary=f"{len(events)} API call(s) in last {window_days}d; latest {last.source}:{last.name} at {last.time:%Y-%m-%d}",
            location=last.event_id,
        )
    ]


def scheduler_targets(sb: Sandbox, role: Role) -> list[Evidence]:
    return [
        Evidence(
            collector="scheduler_targets",
            strength="hard",
            summary=f"EventBridge rule '{t.rule}' ({t.schedule}) runs {t.target_arn} as this role",
            location=f"eventbridge:{t.rule}",
        )
        for t in sb.schedule_targets_for(role.arn)
    ]


def iac_references(sb: Sandbox, role: Role) -> list[Evidence]:
    return [
        Evidence(collector="iac_references", strength="hard", summary="Referenced from Terraform",
                 location=h.location, untrusted_text=h.line)
        for h in sb.grep("iac", role.name, (".tf",))
    ]


def code_references(sb: Sandbox, role: Role) -> list[Evidence]:
    return [
        Evidence(collector="code_references", strength="hard", summary="Referenced from application code",
                 location=h.location, untrusted_text=h.line)
        for h in sb.grep("app", role.name, (".py", ".yaml", ".yml", ".json"))
    ]


def runbook_mentions(sb: Sandbox, role: Role) -> list[Evidence]:
    return [
        Evidence(collector="runbook_mentions", strength="soft", summary="Mentioned in a runbook",
                 location=h.location, untrusted_text=h.line)
        for h in sb.grep("runbooks", role.name, (".md",))
    ]


def resource_metadata(sb: Sandbox, role: Role) -> list[Evidence]:
    out = []
    if role.description:
        out.append(Evidence(collector="resource_metadata", strength="soft", summary="Role description",
                            location=f"{role.arn}#description", untrusted_text=role.description))
    if role.tags:
        tags = ", ".join(f"{k}={v}" for k, v in sorted(role.tags.items()))
        out.append(Evidence(collector="resource_metadata", strength="soft", summary="Role tags",
                            location=f"{role.arn}#tags", untrusted_text=tags))
    return out


REGISTRY: dict[str, Spec] = {
    "cloudtrail_activity": Spec(cloudtrail_activity, "API calls made by the role within window_days", takes_window=True),
    "scheduler_targets": Spec(scheduler_targets, "EventBridge schedules that run a target as the role"),
    "iac_references": Spec(iac_references, "Terraform files that mention the role by name"),
    "code_references": Spec(code_references, "Application code/config that mentions the role by name"),
    "runbook_mentions": Spec(runbook_mentions, "Runbooks that mention the role by name"),
    "resource_metadata": Spec(resource_metadata, "The role's own description and tags (untrusted)"),
}


class PlanRejected(ValueError):
    pass


def compile_plan(plan: EvidencePlan) -> EvidencePlan:
    """Admit a plan only if every call is known and every parameter is in bounds."""
    seen = set()
    for call in plan.collectors:
        spec = REGISTRY.get(call.collector)
        if spec is None:
            raise PlanRejected(f"unknown collector: {call.collector!r}")
        if call.collector in seen:
            raise PlanRejected(f"duplicate collector: {call.collector!r}")
        seen.add(call.collector)
        if spec.takes_window:
            if call.window_days is None or not 1 <= call.window_days <= MAX_RETENTION_DAYS:
                raise PlanRejected(f"{call.collector}: window_days must be 1..{MAX_RETENTION_DAYS}")
        elif call.window_days is not None:
            raise PlanRejected(f"{call.collector}: takes no window_days")
    if "cloudtrail_activity" not in seen:
        raise PlanRejected("plan must include cloudtrail_activity")
    return plan


def collect(sb: Sandbox, role: Role, plan: EvidencePlan) -> list[Evidence]:
    evidence: list[Evidence] = []
    for call in plan.collectors:
        spec = REGISTRY[call.collector]
        if spec.takes_window:
            evidence += spec.fn(sb, role, call.window_days)
        else:
            evidence += spec.fn(sb, role)
    return evidence


def registry_doc() -> str:
    return "\n".join(
        f"- {name}{' (requires window_days, 1..%d)' % MAX_RETENTION_DAYS if s.takes_window else ''}: {s.doc}"
        for name, s in REGISTRY.items()
    )
