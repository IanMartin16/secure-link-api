from datetime import datetime, timezone

from app.models.request import (
    BehaviorInfo,
    DeviceInfo,
    HistoryInfo,
    NetworkInfo,
    RiskEvaluateRequest,
)
from app.services.hybrid_scoring import evaluate_hybrid_risk


def test_evaluate_hybrid_risk():
    payload = RiskEvaluateRequest(
        event_type="login",
        timestamp=datetime(2026, 3, 21, 3, 15, 0, tzinfo=timezone.utc),
        user_id="usr_hybrid_001",
        ip="189.123.45.67",
        device=DeviceInfo(
            device_id="dev_001",
            is_new_device=True,
        ),
        network=NetworkInfo(
            vpn_detected=True,
            proxy_detected=False,
            tor_detected=False,
        ),
        behavior=BehaviorInfo(
            failed_attempts_last_15m=2,
            hourly_pattern_deviation=0.75,
            events_last_10m=7,
            normal_login_hour_start=6,
            normal_login_hour_end=22,
        ),
        history=HistoryInfo(
            recent_event_types=["password_reset", "login", "email_change"],
            new_devices_last_24h=3,
            distinct_ips_last_1h=4,
            distinct_network_types_last_1h=2,
            vpn_switch_count_last_1h=1,
        ),
    )

    result = evaluate_hybrid_risk(payload)

    assert result.rules_score >= 0
    assert result.final_score >= 0
    assert result.fusion_strategy in {"weighted_rules_first", "rules_only"}
    assert result.decision in {"allow", "review", "challenge", "block"}
    assert result.risk_level in {"low", "medium", "high", "critical"}

    if result.fallback_used:
        assert result.ml_score is None
        assert result.model_version is None
    else:
        assert result.ml_score is not None
        assert 0 <= result.ml_score <= 100
        assert result.model_version is not None