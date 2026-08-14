# AGENTS.md

This repository is an evidence-driven black-box autoresearch control plane. Reference code existing in the tree does **not** prove that an external runtime, device, provider, or production system has been validated.

## Read order

Before changing code, read:

1. `README.md` for the product boundary.
2. `docs/ARCHITECTURE.md` for the control-plane and trust model.
3. `docs/INTEGRATION_ROADMAP.md` for unfinished live/production work and issue mapping.
4. `docs/RUNTIME_VALIDATION.md` for maturity levels and Definition of Done.
5. `docs/EVIDENCE_CONTRACT.md` for the evidence required to claim completion.
6. The matching file under `docs/integrations/` before touching a provider/domain integration.

## Maturity language

Use exactly these levels when describing integration status:

- `L0 CONTRACT`: interface/schema exists only.
- `L1 REFERENCE`: deterministic reference implementation/unit tests exist.
- `L2 SANDBOX`: integration was executed in a disposable controlled sandbox.
- `L3 LIVE`: integration was executed against the intended real runtime/device/service with replayable evidence.
- `L4 PRODUCTION`: operational controls, security, observability, provenance, staged rollout and recovery have been validated.

Never infer `L2`, `L3`, or `L4` from the existence of an adapter, fixture, mock, generated command, capability matrix, or unit test.

## Agent execution protocol

For integration work:

1. Select an open issue from `docs/INTEGRATION_ROADMAP.md` whose dependencies are satisfied.
2. Read the corresponding `docs/integrations/*.md` contract.
3. Record the starting maturity and exact target maturity.
4. Build the smallest falsifiable experiment that can advance one maturity boundary.
5. Pin task, candidate, environment, harness, evaluator and policy identities where applicable.
6. Execute only against owned/authorized targets.
7. Capture evidence defined by `docs/EVIDENCE_CONTRACT.md`.
8. Run `bash verify.sh` plus the integration-specific validation command.
9. Do not check an issue acceptance item until the required evidence exists.
10. A PR must state what was proven, what remains unproven, evidence locations/digests, and whether the maturity level changed.

## Fail-closed rules

- A synthetic test cannot close a LIVE validation issue.
- A provider command being generated correctly does not prove the provider executed it.
- An Agent's statement that an action succeeded is not outcome evidence.
- Missing credentials, hardware, provider access, signing material, or deployment infrastructure is a blocker, not a reason to mock success.
- Evaluator/hidden-case material must remain outside candidate-readable/writable surfaces.
- Irreversible external actions require the configured human approval gate.
- Security anomalies resolve to fail-closed/quarantine.

## Repository hygiene

- Keep changes incremental and runnable.
- Reuse the repository's existing tools and test patterns.
- Never commit credentials, personal identifiers, private corpus data, device identifiers, signing material, or absolute home-directory paths.
- Fail loudly with actionable errors; do not silently skip missing dependencies.
- Run the documented test command and inspect the staged diff before every commit.
- Do not bypass hooks or weaken tests to make a change pass.

<!-- BEGIN SHARED RUNTIME IDENTITY -->
## Shared runtime identity and dual-forge preflight
Canonical contract: `ed3c/skills-shared/skills/dual-forge-repository-loop/references/runtime-identity-contract.md`.
Before mutating delivery state, classify runtime from evidence: `CHATGPT_GITHUB_CONNECTOR | GITHUB_ACTIONS | CLAUDE_CODE_LOCAL | CODEX_CLI_LOCAL | CHATGPT_DESKTOP_WORKTREE | UNKNOWN`.
Connector ≠ Actions ≠ local worktree. Local claims require observed checkout/remotes/branch/HEAD; Forgejo requires a resolved local binding; Desktop requires an actually created worktree. `UNKNOWN` fails closed. Runtime, model family, and forge authority are separate. One mutable branch has one writer; runtime/HEAD changes require evidence rebinding.
Dual-forge order: `runtime bind → GitHub ingress → local/Forgejo issue+worktree → verified Forgejo PR → local main → GitHub reconciliation → exact-head Actions → GitHub publication`.
Three qualifying failures trigger fresh diagnosis + new worktree; no fourth blind patch.
<!-- END SHARED RUNTIME IDENTITY -->
