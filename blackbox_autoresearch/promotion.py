"""Promotion gates for moving research candidates toward production."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import PromotionReceipt, PromotionStage


@dataclass(frozen=True)
class PromotionPolicy:
    require_human_for_irreversible: bool = True

    def authorize(
        self,
        *,
        candidate_digest: str,
        stage: PromotionStage,
        evaluator_digest: str,
        environment_digest: str,
        all_guardrails_passed: bool,
        irreversible: bool = False,
        approval_actor: str | None = None,
        rollback_of: str | None = None,
    ) -> PromotionReceipt:
        approved = all_guardrails_passed
        if stage is PromotionStage.PRODUCTION and irreversible and self.require_human_for_irreversible:
            approved = approved and bool(approval_actor)
        actor = approval_actor if approved else None
        return PromotionReceipt(
            candidate_digest=candidate_digest,
            stage=stage,
            evaluator_digest=evaluator_digest,
            environment_digest=environment_digest,
            approved=approved,
            approval_actor=actor,
            rollback_of=rollback_of,
        )
