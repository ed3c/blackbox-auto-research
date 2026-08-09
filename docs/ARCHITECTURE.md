# Trusted black-box autoresearch architecture

## Product boundary

`blackbox-auto-research` is a domain-agnostic research control plane. It owns hypotheses, candidate lineage, bounded experiments, independent verification, evidence-backed decisions, and staged promotion. It does not own a browser, mobile device farm, cloud runtime, or model provider.

```text
Task / Scenario Registry
          |
          v
Experiment Compiler
          |
          v
Search Controller -----> Hypothesis Store
          |
          v
Candidate Generator
          |
          v
Runtime Broker
          |
          v
Environment Adapter ---> opaque target
          |                  |
          |                  v
          +----------> trajectory + state evidence
                             |
                             v
                    Independent Verifier
                             |
                             v
                    Statistical Decision
                             |
                             v
             Evidence Ledger / Promotion Gate
```

## Two nested loops

The outer research loop generates falsifiable hypotheses, ranks them by expected information gain relative to cost and risk, mutates one bounded candidate dimension at a time, then updates belief and lineage from the result.

The inner evaluation loop resets an isolated environment, pins all artifacts by digest, executes within budgets, captures observations and side effects, evaluates the final external state with an independent verifier, and emits evidence for a decision.

## Evidence modes

- `BLACK`: public UI/API/CLI output and externally visible side effects only.
- `GRAY`: BLACK evidence plus logs, traces, database state, network captures, or process metrics.
- `WHITE`: GRAY evidence plus source, AST, LSP, static call graphs, and internal contracts.

Do not merge these modes into one opaque confidence score. A BLACK success demonstrates externally visible behavior; GRAY evidence improves diagnosis; WHITE evidence explains internals and repair quality.

## Trust invariants

1. A candidate cannot be its own evaluator.
2. A candidate-reported metric is never authoritative without independent evidence.
3. Task, candidate, environment, harness, evaluator, and policy identities are immutable digests in each run manifest.
4. Environment reset must be qualified before repeated trials are considered comparable.
5. A verifier must pass golden/initial/planted-bad qualification before it can control promotion.
6. Failed and discarded runs remain replayable evidence.
7. Hard correctness, security, privacy, or irreversible-side-effect guardrails dominate scalar performance.
8. Noisy tasks can resolve to `inconclusive`; safety anomalies resolve to `quarantine`.
9. Irreversible actions require a promotion policy that can demand human approval.

## Search strategies

The v0.2 kernel intentionally does not implement reinforcement learning. Use the simplest strategy that matches the evidence regime:

| Regime | Strategy |
| --- | --- |
| deterministic, cheap | greedy one-variable search |
| noisy alternatives | multi-armed bandit |
| expensive continuous/config search | Bayesian optimization |
| interacting candidate dimensions | population/evolutionary search |
| long-horizon sparse reward | policy optimization after verifier trust is proven |

Search policy is a plug-in above the execution and verification contracts.

## Domain adapters

The same control plane can cover:

- SKILL.md, MCP, tool routing, prompts, model/harness choice, retry policy;
- iOS and Android simulator/emulator and real-device workflows;
- terminal, CI, DevOps, containers, Kubernetes and infrastructure remediation;
- APIs, SDK/protocol compatibility, WebSocket/WebRTC and authentication flows;
- databases, ETL, schema migration and data invariants;
- desktop GUI and legacy enterprise applications;
- customer-support, CRM, calendar and email workflows where backend state is verifiable;
- RAG, search and research agents with claim-level source verification;
- compiler, query-planner, kernel and scheduling optimization;
- authorized security/reliability experiments in isolated environments;
- robotics, IoT and digital twins after simulation and safety gating.

## Provider integration rule

Sandbox and evaluation systems such as OpenShell, Enroot or NeMo Gym belong behind compatibility adapters. Core contracts must not import provider-specific types. This keeps stored manifests and trajectories replayable even when provider APIs change.

## Promotion pipeline

```text
offline replay -> shadow execution -> canary -> approval gate -> production
                                      |                 |
                                      +---- rollback ---+
```

A research-loop win is a candidate result, not production authorization.

## v0.2 reference kernel

The Python package currently provides:

- pinned task/candidate/run contracts;
- BLACK/GRAY/WHITE evidence mode;
- EnvironmentAdapter and independent Verifier protocols;
- deterministic reset fixture;
- verifier qualification against initial/golden/planted-bad states;
- hash-chained evidence events;
- paired repeated-trial decisions with keep/discard/inconclusive/quarantine.

External sandbox execution, provider bridges, multi-device scheduling, advanced search, and production promotion remain separate roadmap slices so their trust boundaries can be tested independently.
