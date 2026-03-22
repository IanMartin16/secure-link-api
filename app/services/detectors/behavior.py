from app.core.policy import get_policy
from app.models.request import RiskEvaluateRequest


def _detect_odd_hours(payload: RiskEvaluateRequest) -> bool:
    if not payload.behavior:
        return False

    start_hour = payload.behavior.normal_login_hour_start
    end_hour = payload.behavior.normal_login_hour_end
    current_hour = payload.timestamp.hour

    if start_hour <= end_hour:
        return current_hour < start_hour or current_hour > end_hour

    return not (current_hour >= start_hour or current_hour <= end_hour)


def _detect_velocity_abuse(payload: RiskEvaluateRequest) -> bool:
    if not payload.behavior:
        return False

    policy = get_policy()
    return payload.behavior.events_last_10m >= policy.thresholds["velocity_events_last_10m"]


def evaluate_behavior_signals(payload: RiskEvaluateRequest) -> tuple[int, list[str]]:
    policy = get_policy()
    score = 0
    reasons: list[str] = []

    behavior = payload.behavior
    if not behavior:
        return score, reasons

    if behavior.failed_attempts_last_15m >= policy.thresholds["failed_attempts_last_15m"]:
        score += policy.rule_weights["multiple_recent_failures"]
        reasons.append("multiple_recent_failures")

    if behavior.hourly_pattern_deviation >= policy.thresholds["behavior_deviation"]:
        score += policy.rule_weights["behavior_out_of_pattern"]
        reasons.append("behavior_out_of_pattern")

    if _detect_odd_hours(payload):
        score += policy.rule_weights["odd_hours_detected"]
        reasons.append("odd_hours_detected")

    if _detect_velocity_abuse(payload):
        score += policy.rule_weights["velocity_abuse_detected"]
        reasons.append("velocity_abuse_detected")

    return score, reasons