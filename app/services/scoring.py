from typing import List, Tuple

from app.core.policy import get_policy
from app.models.internal import ScoreBreakdown
from app.models.request import RiskEvaluateRequest
from app.services.aggregations import build_score_breakdown


def evaluate_risk(
    payload: RiskEvaluateRequest,
) -> Tuple[int, int, List[str], str, str, ScoreBreakdown]:
    policy = get_policy()

    breakdown, reasons = build_score_breakdown(payload)

    rules_score = (
        breakdown.device_subscore
        + breakdown.network_subscore
        + breakdown.behavior_subscore
        + breakdown.geo_subscore
        + breakdown.sequence_subscore
    )

    rules_score = max(0, min(rules_score, 100))
    final_score = rules_score

    if final_score <= policy.decision_ranges.low_max:
        return rules_score, final_score, reasons, "low", "allow", breakdown
    if final_score <= policy.decision_ranges.medium_max:
        return rules_score, final_score, reasons, "medium", "review", breakdown
    if final_score <= policy.decision_ranges.high_max:
        return rules_score, final_score, reasons, "high", "challenge", breakdown
    return rules_score, final_score, reasons, "critical", "block", breakdown