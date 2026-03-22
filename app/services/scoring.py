from typing import List, Tuple

from app.core.policy import get_policy
from app.models.request import RiskEvaluateRequest
from app.services.detectors.behavior import evaluate_behavior_signals
from app.services.detectors.device import evaluate_device_signals
from app.services.detectors.geo import evaluate_geo_signals
from app.services.detectors.network import evaluate_network_signals
from app.services.detectors.sequence import evaluate_sequence_signals


def evaluate_risk(payload: RiskEvaluateRequest) -> Tuple[int, int, List[str], str, str]:
    policy = get_policy()
    rules_score = 0
    reasons: List[str] = []

    detectors = [
        evaluate_device_signals,
        evaluate_network_signals,
        evaluate_behavior_signals,
        evaluate_geo_signals,
        evaluate_sequence_signals,
    ]

    for detector in detectors:
        detector_score, detector_reasons = detector(payload)
        rules_score += detector_score
        reasons.extend(detector_reasons)

    rules_score = min(rules_score, 100)
    final_score = rules_score

    if final_score <= policy.decision_ranges.low_max:
        return rules_score, final_score, reasons, "low", "allow"
    if final_score <= policy.decision_ranges.medium_max:
        return rules_score, final_score, reasons, "medium", "review"
    if final_score <= policy.decision_ranges.high_max:
        return rules_score, final_score, reasons, "high", "challenge"
    return rules_score, final_score, reasons, "critical", "block"