# Design

## 1. Trust boundaries

The pipeline is split by **what each part is allowed to touch**, not by verb.

| Component | LLM? | Credentials | Reads untrusted text? |
|---|---|---|---|
| Planner | yes, once per resource class | none | no |
| Collectors | no | read-only | yes (collects it) |
| Judge | yes, ambiguous residue only | none | yes (fenced in `<untrusted>`) |
| Gate, backtest | no | read-only | no |
| Executor (M1) | **no** | **write, scoped to `iam:PutRolePolicy`/`DeleteRolePolicy`/`TagRole`/`UntagRole` on non-protected roles** | no |
| Watcher (M2) | no; LLM may explain afterwards | read-only | no |

The component that reads attacker-influenceable text (tags, descriptions, code comments) never holds credentials
that can change the account. Prompt injection can at worst produce a wrong *judgement*, which the gate and
backtest check, and which a human approves.

## 2. Guardrails, in order of strength

1. **Deterministic floor.** Hard evidence (a caller in CloudTrail, a schedule, an IaC or code reference) makes
   `dead` impossible, whatever the model says.
2. **Verification not tunable by the model.** The backtest window is fixed at retention (365 days); the plan's
   window only affects triage.
3. **Compiled plans.** The planner chooses from a registry of collectors with bounded parameters. No
   free-form queries, no generated code.
4. **Cite or abstain.** `dormant_by_design` without valid evidence indexes becomes `unknown`.
5. **Human approval** of a candidate list the human channel cannot extend.
6. **Reversibility.** Every apply action is generated with its undo. Quarantine before delete.
7. **Provider guardrails (planned).** Model Armor on Vertex AI screens prompts/responses for injection; it is a
   layer on top, not a replacement for 1–6.

## 3. Observability

M0 records one span per stage and per LLM call to `out/trace.jsonl` (provider, model, tokens, latency). Next:

- export as OpenTelemetry using the GenAI semantic conventions (`gen_ai.operation.name`,
  `gen_ai.request.model`, `gen_ai.usage.input_tokens` …) to Cloud Trace or a self-hosted Langfuse/Phoenix
- per-run cost, and **LLM calls per resource** as a tracked metric (the design target is ≪ 1)
- decision audit log: every verdict with its evidence, who decided (rule / llm / gate / backtest / human)
- eval in CI on every prompt or model change, failing on any harmed needed role

## 4. Roadmap

| Milestone | Scope | Exit criterion |
|---|---|---|
| **M0** ✅ | Offline spike: IAM roles, fixtures, stub LLM, LangGraph + interrupt | `screamtest eval` 2/2 dead, 0/5 needed harmed |
| **M1** | Gemini live on the same fixtures; prompt-injection suite; OTel export | Same score with a real model, N runs, report variance and cost |
| **M2** | Live AWS sandbox: Terraform-seeded traps, read-only boto3 source, executor under a separate role, CloudTrail Lake | Quarantine + automatic rollback on `AccessDenied` via EventBridge |
| **M3** | Durable multi-day watch: graph pauses after quarantine, resumed by EventBridge or a timer (Postgres checkpointer) | Survives restart mid-watch; delete only after second approval |
| **M4** | Second resource class: security-group rules with VPC Flow Logs | Same evaluation table for SG rules |

## 5. Evaluation fixtures

`fixtures/aws-sandbox/labels.json` holds the ground truth and is read only by `screamtest eval`. Each needed
role is a trap for a specific failure:

| Role | Trap | Caught by |
|---|---|---|
| dr-failover-role | idle > 1 year; only referenced from Terraform | IaC collector |
| annual-audit-export-role | yearly cron; last used 273 days ago | scheduler collector |
| breakglass-admin | never used, by design | runbook + judge |
| reports-quarterly-role | prompt injection in its description | gate |
| partner-sftp-sync-role | caller's code is outside the org; 103 days | backtest |
