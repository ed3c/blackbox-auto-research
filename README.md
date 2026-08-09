# blackbox-auto-research

Black-box autoresearch and evidence-driven diagnosis for opaque interactive systems.

The repository provides a domain-agnostic experiment control plane: define a falsifiable task, pin a candidate and evaluator, execute through an environment adapter, collect trajectory/state evidence, make a conservative keep/discard/inconclusive/quarantine decision, and preserve the result for replay.

## Trust kernel

The v0.x line provides:

- immutable task, candidate and run manifests with SHA-256 artifact identities;
- explicit `BLACK`, `GRAY`, and `WHITE` evidence modes;
- separate execution and verifier interfaces;
- verifier qualification and hidden-case separation;
- content-addressed, tamper-evident evidence primitives;
- paired stochastic decisions and pluggable search primitives;
- provider/domain adapters for OpenShell, Enroot, NeMo Gym, mobile and non-UI workloads;
- staged promotion contracts.

These are **reference contracts and implementations**. Adapter existence is not evidence that an external provider, device or production deployment has been validated.

The typed v2 contracts do not replace `autoresearch-ledger/v1`. Ledger v1 remains the lightweight skill-facing experiment format; v2 manifests/evidence are the trusted runtime layer when identity, replay, stochastic evaluation or promotion provenance matters.

## Agent and v1.0 entrypoints

Agents should start with [AGENTS.md](AGENTS.md), then read:

- [architecture](docs/ARCHITECTURE.md)
- [v1.0 integration roadmap](docs/INTEGRATION_ROADMAP.md)
- [runtime validation maturity contract](docs/RUNTIME_VALIDATION.md)
- [evidence contract](docs/EVIDENCE_CONTRACT.md)
- [integration-specific contracts](docs/integrations/)

The v1.0 goal is to move selected integrations from `L1 REFERENCE` / `L2 SANDBOX` to evidence-backed `L3 LIVE` and `L4 PRODUCTION`. Open issues #19-#29 track that work.

## Installable skills

- [autoresearch composer](skills/autoresearch-composer/SKILL.md)
- [full-stack debugger](skills/repo-fullstack-debugger/SKILL.md)
- [experiment-ledger checker](scripts/check_experiment_ledger.py)

## Verify

```bash
bash verify.sh
```

## Delivery history

v0.x contracts and reference implementations are tracked by closed issues #1 and #4-#14. Live/production validation is tracked by open issues #19-#29 and `docs/INTEGRATION_ROADMAP.md`.

License: MIT.
