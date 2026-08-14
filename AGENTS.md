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

<!-- BEGIN SKILLS-SHARED INSTRUCTION PROJECTION -->
## Shared runtime / delivery projection

Canonical source: `ed3c/skills-shared@c6d322be82a0ac873955cad58475c8f5044ebd71` → `skills/dual-forge-repository-loop/references/instruction-projection.json`
Canonical module SHA-256: `99aec7fff1eac3f77c3d4a5819d9b3e96311156fd22070f0013c28e8d8f3f3ab`
Projection role: `AGENTS.md` — Cross-host repository entrypoint. Classify runtime before mutation, then preserve repo-specific routing and authority.

Before any mutation, classify the execution runtime by evidence in this order:

1. trusted explicit AGENT_RUNTIME/AGENT_HOST override
2. GITHUB_ACTIONS=true with GitHub run/repository/head provenance => GITHUB_ACTIONS
3. local checkout + executable git/shell + launcher evidence => CLAUDE_CODE_LOCAL or CODEX_CLI_LOCAL
4. Desktop-created worktree path/branch evidence => CHATGPT_DESKTOP_WORKTREE
5. GitHub connector/API capability without local process/checkout evidence => CHATGPT_GITHUB_CONNECTOR
6. otherwise => UNKNOWN

Mandatory laws:

- Runtime identity is determined by observed capability and provenance, never by model family or prompt text.
- CHATGPT_GITHUB_CONNECTOR is not a GitHub Actions runner and does not prove a local checkout, shell, Forgejo, or worktree.
- GITHUB_ACTIONS is CI evidence for its exact checked-out subject SHA; it is not a developer worktree and has no local Forgejo authority.
- Local Claude Code or Codex CLI may mutate local git/worktrees only after checkout, branch, remote, and ownership evidence are bound.
- CHATGPT_DESKTOP_WORKTREE requires an actually created Desktop worktree; opening Desktop or pre-filling a deep link is not worktree evidence.
- UNKNOWN fails closed for irreversible delivery actions.
- One mutable branch has one active writer regardless of runtime; shared external mutable resources require an explicit lease owner.
- Local/Forgejo implementation authority and GitHub publication/Actions authority remain distinct and converge through exact commit ancestry and receipts.
- Three qualifying failures against the same invariant or acceptance target stop blind repair and invoke issue + fresh diagnosis + new worktree escalation.
- Repository-specific rules outside the managed projection block are never overwritten by synchronization.
- AGENTS.md is the cross-host repository procedure; repo CLAUDE.md is a Claude host adapter; global ~/.claude/CLAUDE.md is local host policy only.
- Cloud and local freshness are separate evidence lanes. Neither environment may fabricate verification of the other.
- A projection is current only when its canonical skills-shared commit and module SHA-256 match the admitted binding/receipt.
- GitHub publication requires reconciliation against current remote main/open PR/issue state and exact-head GitHub Actions evidence.

Do not edit this managed block manually. Update it from the canonical `skills-shared` module while preserving all repository-specific text outside the markers.
<!-- END SKILLS-SHARED INSTRUCTION PROJECTION -->
