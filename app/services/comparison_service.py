from app.models.comparison import ComparisonDelta, RiskComparisonResponse
from app.models.request import RiskEvaluateRequest
from app.models.response import RiskEvaluateResponse
from app.services.hybrid_scoring import evaluate_hybrid_risk
from app.services.scoring import evaluate_risk


def compare_v1_vs_v2(payload: RiskEvaluateRequest) -> RiskComparisonResponse:
    rules_score, final_score, reasons, risk_level, decision, _breakdown = evaluate_risk(payload)

    recommended_action_map = {
        "allow": "none",
        "review": "log_only",
        "challenge": "require_mfa",
        "block": "require_mfa_or_block",
    }

    v1_result = RiskEvaluateResponse(
        request_id="comparison-v1",
        rules_score=rules_score,
        final_score=final_score,
        risk_level=risk_level,
        decision=decision,
        reasons=reasons,
        recommended_action=recommended_action_map[decision],
        engine_version="rules-v1.2",
    )

    v2_result = evaluate_hybrid_risk(payload)

    delta = ComparisonDelta(
        score_difference=v2_result.final_score - v1_result.final_score,
        decision_changed=v2_result.decision != v1_result.decision,
        risk_level_changed=v2_result.risk_level != v1_result.risk_level,
    )

    return RiskComparisonResponse(
        v1_rules_only=v1_result,
        v2_hybrid=v2_result,
        delta=delta,
    )