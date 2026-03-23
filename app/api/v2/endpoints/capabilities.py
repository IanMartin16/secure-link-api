from fastapi import APIRouter

router = APIRouter()


@router.get("/v2/capabilities", tags=["Capabilities v2"])
def get_capabilities_v2() -> dict:
    return {
        "product": "Secure_Link",
        "version": "2.0.0-alpha",
        "engine": "hybrid-v2",
        "description": "Hybrid contextual access risk engine using rules plus ML scoring.",
        "score_components": [
            "rules_score",
            "ml_score",
            "final_score",
        ],
        "fusion": {
            "strategy": "weighted_rules_first",
            "fallback_strategy": "rules_only",
            "critical_override": True,
        },
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
        "model": {
            "model_version": "xgb-001",
            "status": "active",
            "target": "suspicious_or_takeover_like_event_probability",
        },
        "response_fields": [
            "rules_score",
            "ml_score",
            "final_score",
            "risk_level",
            "decision",
            "reasons",
            "fusion_strategy",
            "fallback_used",
            "model_version",
            "engine_version",
        ],
    }