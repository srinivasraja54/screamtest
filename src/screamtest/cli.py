from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .evaluate import baseline, load_labels, score_run, summary
from .graph import run
from .llm import make_llm
from .sandbox import Sandbox
from .telemetry import Recorder

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()

DEFAULT_FIXTURE = Path("fixtures/aws-sandbox")
VERDICT_STYLE = {"active": "green", "dead": "red", "dormant_by_design": "cyan", "unknown": "yellow"}


def _execute(fixture: Path, llm_name: str, approver, out: Path):
    sb, rec = Sandbox(fixture), Recorder()
    state = run(sb, make_llm(llm_name, rec), rec, approver)
    rec.write(out / "trace.jsonl")
    (out / "report.json").write_text(json.dumps({
        "decisions": {k: v.model_dump(mode="json") for k, v in state["decisions"].items()},
        "backtests": {k: v.model_dump(mode="json") for k, v in state.get("backtests", {}).items()},
        "actions": [a.model_dump(mode="json") for a in state.get("actions", [])],
        "summary": summary(state, rec),
    }, indent=2))
    return sb, rec, state


def _print_decisions(state) -> None:
    t = Table(title="Decisions", show_lines=False)
    for col in ("role", "verdict", "by", "reasoning"):
        t.add_column(col)
    for d in state["decisions"].values():
        style = VERDICT_STYLE[d.verdict]
        t.add_row(d.role, f"[{style}]{d.verdict}[/{style}]", d.decided_by, d.reasoning)
    console.print(t)


@app.command("run")
def run_cmd(
    llm: str = typer.Option("stub", help="stub | gemini"),
    fixture: Path = typer.Option(DEFAULT_FIXTURE, help="Sandbox fixture directory"),
    yes: bool = typer.Option(False, "--yes", help="Approve every candidate without asking"),
    out: Path = typer.Option(Path("out"), help="Where report.json and trace.jsonl go"),
):
    """Investigate every IAM role, then propose reversible quarantines for approval."""

    def approver(candidates: list[dict]) -> list[str]:
        if yes:
            return [c["role"] for c in candidates]
        console.rule("Approval required")
        return [c["role"] for c in candidates
                if typer.confirm(f"Quarantine {c['role']}? ({c['reasoning']})", default=False)]

    _, rec, state = _execute(fixture, llm, approver, out)
    _print_decisions(state)
    for a in state["actions"]:
        console.print(f"[bold]quarantine (dry run)[/bold] {a.role}: "
                      f"{', '.join(x['api'] for x in a.apply)}  ⟲ undo: {', '.join(x['api'] for x in a.undo)}")
    console.print(f"\n{summary(state, rec)}\nreport: {out / 'report.json'}  trace: {out / 'trace.jsonl'}")


@app.command("eval")
def eval_cmd(
    llm: str = typer.Option("stub", help="stub | gemini"),
    fixture: Path = typer.Option(DEFAULT_FIXTURE),
    out: Path = typer.Option(Path("out")),
):
    """Score against labels.json. Exits 1 if any needed or active role would be quarantined."""
    sb, rec, state = _execute(fixture, llm, lambda c: [x["role"] for x in c], out)
    labels = load_labels(fixture)
    _print_decisions(state)

    t = Table(title="Evaluation")
    for col in ("approach", "dead roles quarantined", "needed roles harmed", "active roles harmed"):
        t.add_column(col)
    scores = [baseline(sb, labels), score_run(state, labels)]
    for s in scores:
        t.add_row(s.name, "%d/%d" % s.dead_found, "%d/%d" % s.needed_harmed, "%d/%d" % s.active_harmed)
    console.print(t)
    console.print(summary(state, rec))

    ours = scores[-1]
    if ours.needed_harmed[0] or ours.active_harmed[0]:
        console.print("[red]FAIL: a needed or active role would have been quarantined[/red]")
        raise typer.Exit(1)
