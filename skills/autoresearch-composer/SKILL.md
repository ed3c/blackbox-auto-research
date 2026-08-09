---
name: autoresearch-composer
description: |
  Use when a measurable artifact can improve through repeated, bounded experiments. Composes a loop with one metric, one-variable iterations, keep or discard decisions, a durable experiment ledger, regression guards, and explicit stop-loss. Not for open-ended research without an executable evaluator.
---

# Autoresearch composer

An autoresearch loop is an experiment protocol, not repeated prompting.

## Required contract

- goal and scope;
- metric, direction, baseline, and verification command;
- guardrails that must never regress;
- iteration budget and no-progress stop-loss;
- one hypothesis and one bounded change per iteration;
- measured result and explicit `keep` or `discard`;
- final best-known artifact and full cost ledger.

Missing information is `INCOMPLETE`, not guessed.

## Procedure

1. Prove the evaluator can distinguish a good and planted-bad artifact.
2. Capture the baseline and immutable guardrails.
3. Rank hypotheses by expected information gain.
4. Change one variable.
5. Run the same evaluator.
6. Keep only a measured improvement that preserves guardrails; otherwise discard.
7. Record failures and abandoned work in total cost.
8. Stop at the budget, the no-progress limit, or a human decision boundary.

Validate ledgers with `python3 scripts/check_experiment_ledger.py <ledger.json>`.

See [ledger semantics](modules/ledger.md).
