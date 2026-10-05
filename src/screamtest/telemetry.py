"""Minimal run telemetry: every LLM call and every stage, as JSON lines.

Deliberately shaped like OpenTelemetry GenAI spans (operation, model, token
counts, latency) so it can be swapped for a real OTel exporter later.
"""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Span:
    name: str
    kind: str  # "stage" | "llm"
    ms: float = 0.0
    attrs: dict = field(default_factory=dict)


class Recorder:
    def __init__(self) -> None:
        self.spans: list[Span] = []

    @contextmanager
    def span(self, name: str, kind: str = "stage", **attrs):
        s = Span(name, kind, attrs=dict(attrs))
        t0 = time.perf_counter()
        try:
            yield s
        finally:
            s.ms = round((time.perf_counter() - t0) * 1000, 2)
            self.spans.append(s)

    @property
    def llm_calls(self) -> list[Span]:
        return [s for s in self.spans if s.kind == "llm"]

    def tokens(self) -> tuple[int, int]:
        return (
            sum(s.attrs.get("input_tokens", 0) for s in self.llm_calls),
            sum(s.attrs.get("output_tokens", 0) for s in self.llm_calls),
        )

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(asdict(s)) + "\n" for s in self.spans))
