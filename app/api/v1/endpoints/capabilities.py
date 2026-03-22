from fastapi import APIRouter

router = APIRouter()


@router.get("/v1/capabilities", tags=["Capabilities"])
def get_capabilities() -> dict:
    return {
        "product": "Secure_Link",
        "public_capability": "Risk Signals",
        "version": "1.2.0-alpha",
        "capabilities": [
            {
                "name": "risk_evaluation",
                "description": "Evaluates contextual risk for account security events.",
                "score_components": ["rules_score", "final_score"],
                "policy_features": [
                    "configurable_rule_weights",
                    "configurable_thresholds",
                    "configurable_decision_ranges",
                ],
                "supported_event_types": [
                    "login",
                    "password_reset",
                    "email_change",
                    "phone_change",
                    "device_enrollment",
                    "suspicious_access",
                ],
                "supported_signals": [
                    "new_device_detected",
                    "vpn_detected",
                    "proxy_detected",
                    "tor_detected",
                    "multiple_recent_failures",
                    "behavior_out_of_pattern",
                    "new_country_detected",
                    "impossible_travel_detected",
                    "odd_hours_detected",
                    "velocity_abuse_detected",
                    "geo_anomaly_detected",
                    "event_sequence_anomaly",
                    "sensitive_action_burst",
                    "device_churn_detected",
                    "network_switching_anomaly",
                ],
            }
        ],
    }