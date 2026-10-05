"""Score a run against ground-truth labels, next to the naive 90-day baseline."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .graph import State
from .sandbox import Sandbox
from .telemetry import Recorder

BASELINE_DAYS = 90


@dataclass
class Score:
    name: str
    quarantined: set[str]
    labels: dict[str, str]

    def _count(self, truth: str) -> tuple[int, int]:
        roles = {r for r, t in self.labels.items() if t == truth}
        return len(roles & self.quarantined), len(roles)

    @property
    def dead_found(self) -> tuple[int, int]:
        return self._count("dead")

    @property
    def needed_harmed(self) -> tuple[int, int]:
        return self._count("needed")

    @property
    def active_harmed(self) -> tuple[int, int]:
        return self._count("active")


def load_labels(root: Path) -> dict[str, str]:
    raw = json.loads((root / "labels.json").read_text())["labels"]
    return {k: v["truth"] for k, v in raw.items()}


def baseline(sb: Sandbox, labels: dict[str, str]) -> Score:
    """What 'unused for 90 days, delete it' would do."""
    idle = {r.name for r in sb.roles if not sb.events_for(r.arn, BASELINE_DAYS)}
    return Score(f"naive {BASELINE_DAYS}-day rule", idle, labels)


def score_run(state: State, labels: dict[str, str]) -> Score:
    return Score("screamtest", {a.role for a in state.get("actions", [])}, labels)


def summary(state: State, rec: Recorder) -> dict:
    by = {}
    for d in state["decisions"].values():
        by[d.decided_by] = by.get(d.decided_by, 0) + 1
    tin, tout = rec.tokens()
    return {
        "resources": len(state["decisions"]),
        "llm_calls": len(rec.llm_calls),
        "llm_calls_plan": sum(1 for s in rec.llm_calls if s.name == "plan"),
        "llm_calls_judge": sum(1 for s in rec.llm_calls if s.name == "judge"),
        "decided_by": by,
        "tokens_in": tin,
        "tokens_out": tout,
    }
