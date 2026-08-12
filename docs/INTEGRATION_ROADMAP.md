# v1.0 Integration Roadmap

## Purpose

The v0.x line completed provider-neutral contracts and deterministic reference implementations. v1.0 is about **runtime truth**: prove those contracts against real sandboxes, devices, services and production controls.

A closed v0.x issue does not imply a live integration is production-ready.

## Maturity model

| Level | Meaning | Minimum proof |
| --- | --- | --- |
| L0 CONTRACT | schema/interface only | contract tests |
| L1 REFERENCE | deterministic implementation | unit/reference tests |
| L2 SANDBOX | disposable controlled execution | runtime evidence + replay |
| L3 LIVE | intended real runtime/device/service | live evidence + independent verifier |
| L4 PRODUCTION | operationally safe deployment | security + SRE + provenance + rollback |

## Work graph

```text
#19 OpenShell live ───────┐
#20 NeMo Gym live ───────┼──> #23 distributed isolation
#21 Enroot HPC ──────────┤
#22 mobile live ─────────┘

#24 real domain workloads ───────────────┐
                                         ├──> #26 adversarial security
#25 evidence lake ───────────────┐       │
                                 ├──> #28 production promotion
#27 observability/SRE ───────────┘

#19/#20/#21/#22/#24 + #25/#26/#27/#28
                         └──> #29 release readiness
```

## Open v1.0 work

| Issue | Integration | Current | Target | Contract |
| --- | --- | --- | --- | --- |
| #19 | OpenShell | L1 | L3 | `integrations/openshell.md` |
| #20 | NeMo Gym | L1 | L3 | `integrations/nemo-gym.md` |
| #21 | Enroot GPU/HPC | L1 | L3 | `integrations/enroot.md` |
| #22 | iOS + Android | L1 | L3 | `integrations/mobile.md` |
| #23 | distributed/device workers | L1 | L3 | `integrations/distributed-workers.md` |
| #24 | Terminal/MCP/API/Data/CI | L2 | L3 | `integrations/domain-workloads.md` |
| #25 | evidence lake | L2+ | L4 | `integrations/evidence-store.md` |
| #26 | security | L2 | L4 | `integrations/security.md` |
| #27 | observability/SRE | L1 | L4 | `integrations/observability.md` |
| #28 | production promotion | L2 | L4 | `integrations/production-promotion.md` |
| #29 | release engineering | L1 | L4 | `integrations/release.md` |

`L2+` means production-shaped provider-neutral primitives have been added and tested, but the target external object store/KMS/multi-host deployment required for L4 is still unproven.

## Priority

1. Establish at least one L3 execution path: #19 or #24.
2. Prove stored evidence can survive outside the originating worker: #25.
3. Add another independent execution surface: #20 or #22.
4. Prove concurrency/isolation: #23.
5. Attack trust assumptions: #26.
6. Add operational visibility: #27.
7. Validate staged deployment and rollback: #28.
8. Cut v1.0 only after release/supply-chain requirements in #29 pass.

## Status rule

Agents must update this roadmap only when the GitHub issue and evidence agree. Never mark an integration `L3` merely because its adapter exists or a CI mock passed.
