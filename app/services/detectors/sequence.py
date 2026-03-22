from app.core.policy import get_policy
from app.models.request import RiskEvaluateRequest

SUSPICIOUS_SEQUENCES = {
    ("password_reset", "login"),
    ("login", "email_change"),
    ("device_enrollment", "phone_change"),
    ("login", "phone_change"),
}

SENSITIVE_EVENT_TYPES = {
    "login",
    "password_reset",
    "email_change",
    "phone_change",
    "device_enrollment",
    "suspicious_access",
}


def _detect_event_sequence_anomaly(payload: RiskEvaluateRequest) -> bool:
    if not payload.history or not payload.history.recent_event_types:
        return False

    recent = payload.history.recent_event_types
    last_event = recent[-1]
    current_event = payload.event_type

    return (last_event, current_event) in SUSPICIOUS_SEQUENCES


def _detect_sensitive_action_burst(payload: RiskEvaluateRequest) -> bool:
    if not payload.history:
        return False

    policy = get_policy()
    recent = payload.history.recent_event_types or []
    current_event = payload.event_type

    if current_event not in SENSITIVE_EVENT_TYPES:
        return False

    sensitive_count = sum(1 for event in recent if event in SENSITIVE_EVENT_TYPES)

    return sensitive_count >= policy.thresholds["sensitive_action_burst_count"]


def evaluate_sequence_signals(payload: RiskEvaluateRequest) -> tuple[int, list[str]]:
    policy = get_policy()
    score = 0
    reasons: list[str] = []

    if _detect_event_sequence_anomaly(payload):
        score += policy.rule_weights["event_sequence_anomaly"]
        reasons.append("event_sequence_anomaly")

    if _detect_sensitive_action_burst(payload):
        score += policy.rule_weights["sensitive_action_burst"]
        reasons.append("sensitive_action_burst")

    return score, reasons