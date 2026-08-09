# blackbox-auto-research

Black-box autoresearch and evidence-driven diagnosis for opaque interactive systems.

The repository provides a domain-agnostic experiment control plane: define a falsifiable task, pin a candidate and evaluator, execute through an environment adapter, collect trajectory/state evidence, make a conservative keep/discard/inconclusive/quarantine decision, and preserve the result for replay.

## Trust kernel

The v0.2 Python kernel adds:

- immutable task, candidate and run manifests with SHA-256 artifact identities;
- explicit `BLACK`, `GRAY`, and `WHITE` evidence modes;
- separate `EnvironmentAdapter` and `Verifier` interfaces;
- verifier qualification against golden, initial and planted-bad states;
- tamper-evident hash-chained evidence events;
- paired repeated-trial decisions with hard-guardrail precedence;
- deterministic fake target tests for reset isolation.

See [architecture and domain adapters](docs/ARCHITECTURE.md).

## Installable skills

- [autoresearch composer](skills/autoresearch-composer/SKILL.md)
- [full-stack debugger](skills/repo-fullstack-debugger/SKILL.md)
- [experiment-ledger checker](scripts/check_experiment_ledger.py)

## Verify

```bash
bash verify.sh
```

## Delivery

- PRD: [#1](https://github.com/ed3c/blackbox-auto-research/issues/1)
- trusted contracts: [#4](https://github.com/ed3c/blackbox-auto-research/issues/4)
- adapter SDK: [#5](https://github.com/ed3c/blackbox-auto-research/issues/5)
- runtime isolation: [#6](https://github.com/ed3c/blackbox-auto-research/issues/6)
- verifier qualification: [#7](https://github.com/ed3c/blackbox-auto-research/issues/7)
- evidence replay: [#8](https://github.com/ed3c/blackbox-auto-research/issues/8)
- stochastic decisions and search: [#9](https://github.com/ed3c/blackbox-auto-research/issues/9), [#10](https://github.com/ed3c/blackbox-auto-research/issues/10)
- provider and domain bridges: [#11](https://github.com/ed3c/blackbox-auto-research/issues/11), [#12](https://github.com/ed3c/blackbox-auto-research/issues/12), [#13](https://github.com/ed3c/blackbox-auto-research/issues/13)
- staged promotion: [#14](https://github.com/ed3c/blackbox-auto-research/issues/14)

License: MIT.
