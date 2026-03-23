from app.core.policy import get_policy
from app.models.request import RiskEvaluateRequest


def get_network_switching_flag(payload: RiskEvaluateRequest) -> int:
    if not payload.history:
        return 0

    history = payload.history
    policy = get_policy()

    detected = (
        history.distinct_ips_last_1h >= policy.thresholds["distinct_ips_last_1h"]
        or history.distinct_network_types_last_1h >= policy.thresholds["distinct_network_types_last_1h"]
        or history.vpn_switch_count_last_1h >= policy.thresholds["vpn_switch_count_last_1h"]
    )
    return 1 if detected else 0


def evaluate_network_signals(payload: RiskEvaluateRequest) -> tuple[int, list[str]]:
    policy = get_policy()
    score = 0
    reasons: list[str] = []

    network = payload.network
    if network:
        if network.vpn_detected:
            score += policy.rule_weights["vpn_detected"]
            reasons.append("vpn_detected")

        if network.proxy_detected:
            score += policy.rule_weights["proxy_detected"]
            reasons.append("proxy_detected")

        if network.tor_detected:
            score += policy.rule_weights["tor_detected"]
            reasons.append("tor_detected")

    if get_network_switching_flag(payload):
        score += policy.rule_weights["network_switching_anomaly"]
        reasons.append("network_switching_anomaly")

    return score, reasons