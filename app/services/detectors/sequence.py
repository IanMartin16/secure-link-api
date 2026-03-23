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


def get_event_sequence_anomaly_flag(payload: RiskEvaluateRequest) -> int:
    if not payload.history or not payload.history.recent_event_types:
        return 0

    recent = payload.history.recent_event_types
    last_event = recent[-1]
    current_event = payload.event_type

    return 1 if (last_event, current_event) in SUSPICIOUS_SEQUENCES else 0


def get_sensitive_action_burst_flag(payload: RiskEvaluateRequest) -> int:
    if not payload.history:
        return 0

    policy = get_policy()
    recent = payload.history.recent_event_types or []
    current_event = payload.event_type

    if current_event not in SENSITIVE_EVENT_TYPES:
        return 0

    sensitive_count = sum(1 for event in recent if event in SENSITIVE_EVENT_TYPES)

    return 1 if sensitive_count >= policy.thresholds["sensitive_action_burst_count"] else 0


def evaluate_sequence_signals(payload: RiskEvaluateRequest) -> tuple[int, list[str]]:
    policy = get_policy()
    score = 0
    reasons: list[str] = []

    if get_event_sequence_anomaly_flag(payload):
        score += policy.rule_weights["event_sequence_anomaly"]
        reasons.append("event_sequence_anomaly")

    if get_sensitive_action_burst_flag(payload):
        score += policy.rule_weights["sensitive_action_burst"]
        reasons.append("sensitive_action_burst")

    return score, reasons