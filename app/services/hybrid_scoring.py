from __future__ import annotations

from typing import Tuple

from app.core.policy import get_policy
from app.models.hybrid import HybridEvaluationResult
from app.models.request import RiskEvaluateRequest
from app.services.feature_builder import build_feature_record
from app.services.ml_score_service import predict_ml_score
from app.services.scoring import evaluate_risk


CRITICAL_REASONS = {
    "impossible_travel_detected",
    "tor_detected",
}


def _has_critical_override(reasons: list[str]) -> bool:
    if any(reason in CRITICAL_REASONS for reason in reasons):
        return True

    reason_set = set(reasons)

    if {"new_device_detected", "sensitive_action_burst"}.issubset(reason_set):
        return True

    if {"device_churn_detected", "network_switching_anomaly"}.issubset(reason_set):
        return True

    return False


def _resolve_decision(final_score: int) -> Tuple[str, str]:
    policy = get_policy()

    if final_score <= policy.decision_ranges.low_max:
        return "low", "allow"
    if final_score <= policy.decision_ranges.medium_max:
        return "medium", "review"
    if final_score <= policy.decision_ranges.high_max:
        return "high", "challenge"
    return "critical", "block"


def evaluate_hybrid_risk(payload: RiskEvaluateRequest) -> HybridEvaluationResult:
    rules_score, _final_score, reasons, _risk_level, _decision, breakdown = evaluate_risk(payload)

    feature_record = build_feature_record(
        payload=payload,
        breakdown=breakdown,
        rules_score=rules_score,
    )

    try:
        ml_result = predict_ml_score(feature_record)
        ml_score = ml_result["ml_score"]
        fused_score = int(round((0.7 * rules_score) + (0.3 * ml_score)))

        if _has_critical_override(reasons):
            final_score = max(rules_score, fused_score)
        else:
            final_score = fused_score

        final_score = min(final_score, 100)
        risk_level, decision = _resolve_decision(final_score)

        return HybridEvaluationResult(
            rules_score=rules_score,
            ml_score=ml_score,
            final_score=final_score,
            risk_level=risk_level,
            decision=decision,
            reasons=reasons,
            fusion_strategy="weighted_rules_first",
            fallback_used=False,
            model_version=ml_result["model_version"],
            engine_version="hybrid-v2",
        )

    except Exception:
        final_score = rules_score
        risk_level, decision = _resolve_decision(final_score)

        return HybridEvaluationResult(
            rules_score=rules_score,
            ml_score=None,
            final_score=final_score,
            risk_level=risk_level,
            decision=decision,
            reasons=reasons,
            fusion_strategy="rules_only",
            fallback_used=True,
            model_version=None,
            engine_version="rules-only-fallback",
        )