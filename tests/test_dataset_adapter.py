from datetime import datetime, timezone

from app.models.request import (
    BehaviorInfo,
    DeviceInfo,
    HistoryInfo,
    NetworkInfo,
    RiskEvaluateRequest,
)
from app.services.dataset_adapter import build_dataset_row_from_payload


def test_build_dataset_row_from_payload():
    payload = RiskEvaluateRequest(
        event_type="login",
        timestamp=datetime(2026, 3, 21, 3, 15, 0, tzinfo=timezone.utc),
        user_id="usr_adapter_001",
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

    row = build_dataset_row_from_payload(payload, label_suspicious=1)

    assert row["event_type"] == "login"
    assert row["is_new_device"] == 1
    assert row["vpn_detected"] == 1
    assert row["rules_score"] >= 0
    assert row["final_score"] >= 0
    assert row["decision"] in {"allow", "review", "challenge", "block"}
    assert row["label_suspicious"] == 1