"""The pipeline as a LangGraph state graph.

    plan ─► collect ─► judge ─► backtest ─► approve (human) ─► quarantine
    LLM     rules      rules+   data         interrupt()        dry run
    once               LLM on
                       residue

Only `plan` and part of `judge` call a model. Nothing in this graph holds write
credentials; `quarantine` emits actions for a separate executor.
"""

from __future__ import annotations

from typing import Callable, TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from .collectors import collect, compile_plan
from .decide import backtest, gate, triage
from .llm import LLM
from .models import BacktestResult, Decision, Evidence, EvidencePlan, QuarantineAction
from .quarantine import plan_quarantine
from .sandbox import Sandbox
from .telemetry import Recorder


class State(TypedDict, total=False):
    plan: EvidencePlan
    evidence: dict[str, list[Evidence]]
    decisions: dict[str, Decision]
    backtests: dict[str, BacktestResult]
    approved: list[str]
    actions: list[QuarantineAction]


def build_graph(sb: Sandbox, llm: LLM, rec: Recorder, checkpointer=None):
    roles = {r.name: r for r in sb.roles}

    def plan_node(state: State) -> State:
        plan = llm.propose_plan("aws_iam_role")
        with rec.span("compile_plan"):
            return {"plan": compile_plan(plan)}

    def collect_node(state: State) -> State:
        with rec.span("collect", resources=len(roles)):
            return {"evidence": {n: collect(sb, r, state["plan"]) for n, r in roles.items()}}

    def judge_node(state: State) -> State:
        decisions = {}
        for name, role in roles.items():
            ev = state["evidence"][name]
            decisions[name] = triage(role, ev) or gate(role, ev, llm.judge(role, ev))
        return {"decisions": decisions}

    def backtest_node(state: State) -> State:
        decisions, results = dict(state["decisions"]), {}
        with rec.span("backtest"):
            for name, d in state["decisions"].items():
                if d.verdict != "dead":
                    continue
                bt = results[name] = backtest(sb, roles[name])
                if not bt.passed:
                    decisions[name] = d.model_copy(update={
                        "verdict": "unknown", "decided_by": "backtest",
                        "reasoning": f"Would have broken {len(bt.would_break)} call(s) in the last "
                                     f"{bt.window_days}d: {bt.would_break[0]}",
                    })
        return {"decisions": decisions, "backtests": results}

    def approve_node(state: State) -> State:
        candidates = [n for n, d in state["decisions"].items() if d.verdict == "dead"]
        if not candidates:
            return {"approved": []}
        answer = interrupt({"candidates": [
            {"role": n, "reasoning": state["decisions"][n].reasoning} for n in candidates
        ]})
        # Whatever comes back from the human channel is filtered to the candidate set.
        return {"approved": [n for n in answer if n in candidates]}

    def quarantine_node(state: State) -> State:
        return {"actions": [plan_quarantine(n, sb.now) for n in state["approved"]]}

    g = StateGraph(State)
    for name, fn in [("plan", plan_node), ("collect", collect_node), ("judge", judge_node),
                     ("backtest", backtest_node), ("approve", approve_node), ("quarantine", quarantine_node)]:
        g.add_node(name, fn)
    g.add_edge(START, "plan")
    g.add_edge("plan", "collect")
    g.add_edge("collect", "judge")
    g.add_edge("judge", "backtest")
    g.add_edge("backtest", "approve")
    g.add_edge("approve", "quarantine")
    g.add_edge("quarantine", END)
    return g.compile(checkpointer=checkpointer or InMemorySaver())


Approver = Callable[[list[dict]], list[str]]


def run(sb: Sandbox, llm: LLM, rec: Recorder, approver: Approver, thread_id: str = "run") -> State:
    graph = build_graph(sb, llm, rec)
    config = {"configurable": {"thread_id": thread_id}}
    state = graph.invoke({}, config)
    while "__interrupt__" in state:
        request = state["__interrupt__"][0].value
        state = graph.invoke(Command(resume=approver(request["candidates"])), config)
    return state
