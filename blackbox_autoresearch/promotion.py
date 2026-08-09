"""Promotion gates for moving research candidates toward production."""

from __future__ import annotations

from dataclasses import dataclass, field

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


_STAGE_ORDER = (
    PromotionStage.OFFLINE,
    PromotionStage.SHADOW,
    PromotionStage.CANARY,
    PromotionStage.PRODUCTION,
)


@dataclass
class PromotionPipeline:
    """Stateful gate controller; a research win cannot skip deployment stages."""

    candidate_digest: str
    evaluator_digest: str
    environment_digest: str
    policy: PromotionPolicy = field(default_factory=PromotionPolicy)
    receipts: list[PromotionReceipt] = field(default_factory=list)

    def _next_stage(self) -> PromotionStage:
        approved = [receipt.stage for receipt in self.receipts if receipt.approved and receipt.stage is not PromotionStage.ROLLBACK]
        if not approved:
            return PromotionStage.OFFLINE
        last = approved[-1]
        if last is PromotionStage.PRODUCTION:
            raise RuntimeError("candidate already promoted to production")
        return _STAGE_ORDER[_STAGE_ORDER.index(last) + 1]

    def advance(
        self,
        stage: PromotionStage,
        *,
        all_guardrails_passed: bool,
        observed_evaluator_digest: str | None = None,
        observed_environment_digest: str | None = None,
        irreversible: bool = False,
        approval_actor: str | None = None,
    ) -> PromotionReceipt:
        if stage is PromotionStage.ROLLBACK:
            raise ValueError("use rollback() for rollback receipts")
        expected = self._next_stage()
        if stage is not expected:
            raise RuntimeError(f"promotion stage must be {expected.value}, got {stage.value}")
        if observed_evaluator_digest is not None and observed_evaluator_digest != self.evaluator_digest:
            all_guardrails_passed = False
        if observed_environment_digest is not None and observed_environment_digest != self.environment_digest:
            all_guardrails_passed = False
        receipt = self.policy.authorize(
            candidate_digest=self.candidate_digest,
            stage=stage,
            evaluator_digest=self.evaluator_digest,
            environment_digest=self.environment_digest,
            all_guardrails_passed=all_guardrails_passed,
            irreversible=irreversible,
            approval_actor=approval_actor,
        )
        self.receipts.append(receipt)
        return receipt

    def rollback(self, *, failed_candidate_digest: str, approval_actor: str | None = None) -> PromotionReceipt:
        receipt = self.policy.authorize(
            candidate_digest=self.candidate_digest,
            stage=PromotionStage.ROLLBACK,
            evaluator_digest=self.evaluator_digest,
            environment_digest=self.environment_digest,
            all_guardrails_passed=True,
            approval_actor=approval_actor,
            rollback_of=failed_candidate_digest,
        )
        self.receipts.append(receipt)
        return receipt

    def production_drifted(self, *, evaluator_digest: str, environment_digest: str) -> bool:
        return evaluator_digest != self.evaluator_digest or environment_digest != self.environment_digest
