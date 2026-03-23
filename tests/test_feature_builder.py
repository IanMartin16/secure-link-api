from datetime import datetime, timezone

from app.models.internal import ScoreBreakdown
from app.models.request import (
    BehaviorInfo,
    DeviceInfo,
    GeoInfo,
    HistoryInfo,
    NetworkInfo,
    RiskEvaluateRequest,
)
from app.services.feature_builder import build_feature_record


def test_build_feature_record():
    payload = RiskEvaluateRequest(
        event_type="login",
        timestamp=datetime(2026, 3, 21, 3, 15, 0, tzinfo=timezone.utc),
        user_id="usr_200",
        ip="189.123.45.67",
        geo=GeoInfo(
            country="MX",
            city="CDMX",
            latitude=19.4326,
            longitude=-99.1332,
        ),
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
            previous_geo=GeoInfo(
                country="US",
                city="Austin",
                latitude=30.2672,
                longitude=-97.7431,
            ),
            previous_login_at=datetime(2026, 3, 21, 1, 15, 0, tzinfo=timezone.utc),
        ),
    )

    breakdown = ScoreBreakdown(
        device_subscore=38,
        network_subscore=31,
        behavior_subscore=25,
        geo_subscore=18,
        sequence_subscore=22,
        active_signal_count=7,
        recent_sensitive_event_count=3,
        country_changed_flag=1,
        distance_from_previous_km=1200.0,
    )

    record = build_feature_record(
        payload=payload,
        breakdown=breakdown,
        rules_score=100,
    )

    assert record["event_type"] == "login"
    assert record["current_hour"] == 3
    assert record["is_sensitive_event"] == 1
    assert record["is_new_device"] == 1
    assert record["vpn_detected"] == 1
    assert record["failed_attempts_last_15m"] == 2
    assert record["hourly_pattern_deviation"] == 0.75
    assert record["events_last_10m"] == 7
    assert record["new_devices_last_24h"] == 3
    assert record["distinct_ips_last_1h"] == 4
    assert record["country_changed_flag"] == 1
    assert record["rules_score"] == 100
    assert record["active_signal_count"] == 7
    assert record["device_subscore"] == 38
    assert record["sequence_subscore"] == 22

    assert record["impossible_travel_flag"] in (0, 1)
    assert record["geo_anomaly_flag"] in (0, 1)
    assert record["event_sequence_anomaly_flag"] == 0
    assert record["sensitive_action_burst_flag"] == 1
    assert record["device_churn_flag"] == 1
    assert record["network_switching_flag"] == 1