from app.models.request import RiskEvaluateRequest
from app.core.policy import get_policy


def _detect_device_churn(payload: RiskEvaluateRequest) -> bool:
    if not payload.history:
        return False

    policy = get_policy()
    return payload.history.new_devices_last_24h >= policy.thresholds["device_churn_last_24h"]

def evaluate_device_signals(payload: RiskEvaluateRequest) -> tuple[int, list[str]]:
    policy = get_policy()
    score = 0
    reasons: list[str] = []

    device = payload.device
    if device and device.is_new_device:
        score += policy.rule_weights["new_device_detected"]
        reasons.append("new_device_detected")

    if _detect_device_churn(payload):
        score += policy.rule_weights["device_churn_detected"]
        reasons.append("device_churn_detected")

    return score, reasons