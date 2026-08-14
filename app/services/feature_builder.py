from __future__ import annotations

from typing import Any

from app.models.internal import ScoreBreakdown
from app.models.request import RiskEvaluateRequest
from app.services.detectors.device import get_device_churn_flag
from app.services.detectors.geo import (
    get_distance_km,
    get_geo_anomaly_flag,
    get_impossible_travel_flag,
)
from app.services.detectors.network import get_network_switching_flag
from app.services.detectors.sequence import (
    SENSITIVE_EVENT_TYPES,
    get_event_sequence_anomaly_flag,
    get_sensitive_action_burst_flag,
)


FEATURE_SCHEMA_VERSION = "secure-link-features-v1"

FEATURE_COLUMNS_V1: tuple[str, ...] = (
    "event_type",
    "current_hour",
    "is_sensitive_event",
    "is_new_device",
    "vpn_detected",
    "proxy_detected",
    "tor_detected",
    "failed_attempts_last_15m",
    "hourly_pattern_deviation",
    "events_last_10m",
    "new_devices_last_24h",
    "distinct_ips_last_1h",
    "distinct_network_types_last_1h",
    "vpn_switch_count_last_1h",
    "country_changed_flag",
    "distance_from_previous_km",
    "impossible_travel_flag",
    "geo_anomaly_flag",
    "event_sequence_anomaly_flag",
    "sensitive_action_burst_flag",
    "device_churn_flag",
    "network_switching_flag",
    "rules_score",
    "active_signal_count",
    "recent_sensitive_event_count",
    "device_subscore",
    "network_subscore",
    "behavior_subscore",
    "geo_subscore",
    "sequence_subscore",
)


def _safe_bool_as_int(value: bool) -> int:
    return int(bool(value))


def _count_recent_sensitive_events(payload: RiskEvaluateRequest) -> int:
    if payload.history is None:
        return 0

    recent_events = payload.history.recent_event_types or []

    return sum(
        1
        for event_type in recent_events
        if event_type in SENSITIVE_EVENT_TYPES
    )


def _validate_feature_contract(
    record: dict[str, Any],
) -> dict[str, Any]:
    expected_columns = set(FEATURE_COLUMNS_V1)
    actual_columns = set(record)

    missing_columns = expected_columns - actual_columns
    extra_columns = actual_columns - expected_columns

    if missing_columns or extra_columns:
        raise ValueError(
            "Feature contract mismatch for "
            f"{FEATURE_SCHEMA_VERSION}. "
            f"Missing={sorted(missing_columns)}, "
            f"extra={sorted(extra_columns)}"
        )

    # También garantiza un orden estable de las columnas.
    return {
        column: record[column]
        for column in FEATURE_COLUMNS_V1
    }


def build_feature_record(
    payload: RiskEvaluateRequest,
    breakdown: ScoreBreakdown,
    rules_score: int,
) -> dict[str, Any]:
    device = payload.device
    network = payload.network
    behavior = payload.behavior
    history = payload.history

    distance_km = get_distance_km(payload)

    record: dict[str, Any] = {
        "event_type": payload.event_type,
        "current_hour": payload.timestamp.hour,
        "is_sensitive_event": _safe_bool_as_int(
            payload.event_type in SENSITIVE_EVENT_TYPES
        ),
        "is_new_device": _safe_bool_as_int(
            device.is_new_device if device else False
        ),
        "vpn_detected": _safe_bool_as_int(
            network.vpn_detected if network else False
        ),
        "proxy_detected": _safe_bool_as_int(
            network.proxy_detected if network else False
        ),
        "tor_detected": _safe_bool_as_int(
            network.tor_detected if network else False
        ),
        "failed_attempts_last_15m": (
            behavior.failed_attempts_last_15m
            if behavior
            else 0
        ),
        "hourly_pattern_deviation": (
            behavior.hourly_pattern_deviation
            if behavior
            else 0.0
        ),
        "events_last_10m": (
            behavior.events_last_10m
            if behavior
            else 0
        ),
        "new_devices_last_24h": (
            history.new_devices_last_24h
            if history
            else 0
        ),
        "distinct_ips_last_1h": (
            history.distinct_ips_last_1h
            if history
            else 0
        ),
        "distinct_network_types_last_1h": (
            history.distinct_network_types_last_1h
            if history
            else 0
        ),
        "vpn_switch_count_last_1h": (
            history.vpn_switch_count_last_1h
            if history
            else 0
        ),
        "country_changed_flag": breakdown.country_changed_flag,
        "distance_from_previous_km": (
            round(distance_km, 2)
            if distance_km is not None
            else 0.0
        ),
        "impossible_travel_flag": get_impossible_travel_flag(payload),
        "geo_anomaly_flag": get_geo_anomaly_flag(payload),
        "event_sequence_anomaly_flag": (
            get_event_sequence_anomaly_flag(payload)
        ),
        "sensitive_action_burst_flag": (
            get_sensitive_action_burst_flag(payload)
        ),
        "device_churn_flag": get_device_churn_flag(payload),
        "network_switching_flag": (
            get_network_switching_flag(payload)
        ),
        "rules_score": rules_score,
        "active_signal_count": breakdown.active_signal_count,
        "recent_sensitive_event_count": (
            _count_recent_sensitive_events(payload)
        ),
        "device_subscore": breakdown.device_subscore,
        "network_subscore": breakdown.network_subscore,
        "behavior_subscore": breakdown.behavior_subscore,
        "geo_subscore": breakdown.geo_subscore,
        "sequence_subscore": breakdown.sequence_subscore,
    }

    return _validate_feature_contract(record)