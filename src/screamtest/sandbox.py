"""Read-only view of an account, backed by fixtures.

M0 reads JSON fixtures. A live AWS source (boto3, read-only role) implements the
same surface later; nothing downstream should know the difference.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from .models import Role


@dataclass(frozen=True)
class TrailEvent:
    event_id: str
    time: datetime
    name: str
    source: str
    role_arn: str


@dataclass(frozen=True)
class ScheduleTarget:
    rule: str
    schedule: str
    target_arn: str
    role_arn: str


@dataclass(frozen=True)
class TextHit:
    location: str  # path:line, relative to the sandbox root
    line: str


class Sandbox:
    def __init__(self, root: Path):
        self.root = root
        meta = json.loads((root / "roles.json").read_text())
        self.now = _ts(meta["now"])
        self.roles = [Role.model_validate(r) for r in meta["roles"]]
        self._events = [
            TrailEvent(e["eventID"], _ts(e["eventTime"]), e["eventName"], e["eventSource"], e["roleArn"])
            for e in map(json.loads, (root / "cloudtrail.jsonl").read_text().splitlines())
        ]
        rules = json.loads((root / "eventbridge_rules.json").read_text())["rules"]
        self._targets = [
            ScheduleTarget(r["name"], r["schedule"], t["arn"], t["roleArn"])
            for r in rules
            for t in r["targets"]
        ]

    def events_for(self, role_arn: str, window_days: int) -> list[TrailEvent]:
        since = self.now - timedelta(days=window_days)
        hits = [e for e in self._events if e.role_arn == role_arn and e.time >= since]
        return sorted(hits, key=lambda e: e.time, reverse=True)

    def schedule_targets_for(self, role_arn: str) -> list[ScheduleTarget]:
        return [t for t in self._targets if t.role_arn == role_arn]

    def grep(self, subdir: str, needle: str, suffixes: tuple[str, ...]) -> list[TextHit]:
        hits = []
        for path in sorted((self.root / subdir).rglob("*")):
            if not path.is_file() or path.suffix not in suffixes:
                continue
            for n, line in enumerate(path.read_text().splitlines(), start=1):
                if needle in line:
                    hits.append(TextHit(f"{path.relative_to(self.root)}:{n}", line.strip()))
        return hits


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
