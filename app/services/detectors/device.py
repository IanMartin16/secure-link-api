from app.core.policy import get_policy
from app.models.request import RiskEvaluateRequest


def get_device_churn_flag(payload: RiskEvaluateRequest) -> int:
    if not payload.history:
        return 0

    policy = get_policy()
    return 1 if payload.history.new_devices_last_24h >= policy.thresholds["device_churn_last_24h"] else 0


def evaluate_device_signals(payload: RiskEvaluateRequest) -> tuple[int, list[str]]:
    policy = get_policy()
    score = 0
    reasons: list[str] = []

    device = payload.device
    if device and device.is_new_device:
        score += policy.rule_weights["new_device_detected"]
        reasons.append("new_device_detected")

    if get_device_churn_flag(payload):
        score += policy.rule_weights["device_churn_detected"]
        reasons.append("device_churn_detected")

    return score, reasons