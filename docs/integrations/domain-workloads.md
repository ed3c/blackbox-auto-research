# Terminal, MCP, API, Data and CI Workloads

Issue: #24

```yaml
current_maturity: L1_REFERENCE
target_maturity: L3_LIVE
```

## Agent task

For each domain, add one owned/disposable workload whose success is determined by external state rather than Agent narration.

## Required workloads

- CLI/repository: command or patch changes a verifiable repository/file/test state;
- MCP: expected tool routing and final side effect;
- API: state-machine transition with idempotency/error behavior;
- database/ETL: invariant-preserving transformation and rollback;
- CI: seeded failure repaired in a disposable project;
- differential: seeded behavioral regression detected;
- metamorphic: transformed input preserves/violates a declared invariant as expected.

## Done

#24 closes when every listed workload emits the common Evidence Contract and can be replayed/reverified without trusting candidate prose.
