# Terminal, MCP, API, Data and CI Workloads

Issue: #24

```yaml
current_maturity: L2_SANDBOX
target_maturity: L3_LIVE
```

## Current proof

The repository now executes disposable stdlib-backed workloads in CI rather than only calling pure verifier fixtures:

- a subprocess mutates a real temporary filesystem and a separate verifier checks final file bytes;
- a real loopback HTTP server receives an MCP-shaped tool call and an independent call log verifies routing;
- a stateful API object executes valid transitions and rejects an invalid transition;
- a real SQLite transaction executes ETL, checks a sum invariant, then proves rollback;
- a disposable unittest project is seeded red, repaired, and required to turn green;
- differential and metamorphic checks detect planted regressions/invariant violations;
- all results are projected into `blackbox-domain-evidence/v1` with SHA-256 outcome digests.

This is L2 because the workloads execute real process/network/database boundaries inside the controlled CI sandbox. It is not L3: no external MCP service, API provider, production-like database, or external CI control plane is involved.

## Agent task for L3

For each domain, replace or supplement the disposable local target with one owned external/intended runtime whose success is determined by external state rather than Agent narration.

## Required L3 workloads

- CLI/repository: command or patch against an independently provisioned disposable repository/workspace;
- MCP: intended MCP server/runtime with expected tool routing and final side effect;
- API: external sandbox state-machine transition with idempotency/error behavior;
- database/ETL: independently provisioned database/ETL service with invariant and rollback evidence;
- CI: actual disposable CI control plane run whose seeded failure is repaired;
- differential: seeded behavioral regression detected against two independently executed candidates;
- metamorphic: transformed input preserves/violates a declared invariant as expected;
- common evidence must persist outside the originating process.

## Done

#24 closes only when every listed domain has L3 evidence under `docs/EVIDENCE_CONTRACT.md`. The current CI suite proves L2 and must not be used to claim L3.
