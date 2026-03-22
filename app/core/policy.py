from functools import lru_cache

from pydantic import BaseModel, Field


class DecisionRanges(BaseModel):
    low_max: int = 29
    medium_max: int = 59
    high_max: int = 79


class PolicyConfig(BaseModel):
    rule_weights: dict[str, int] = Field(
        default_factory=lambda: {
            "new_device_detected": 20,
            "vpn_detected": 15,
            "proxy_detected": 10,
            "tor_detected": 30,
            "multiple_recent_failures": 20,
            "behavior_out_of_pattern": 10,
            "new_country_detected": 15,
            "impossible_travel_detected": 40,
            "odd_hours_detected": 15,
            "velocity_abuse_detected": 20,
            "geo_anomaly_detected": 18,
            "event_sequence_anomaly": 20,
            "sensitive_action_burst": 22,
            "device_churn_detected": 18,
            "network_switching_anomaly": 16,
        }
    )

    thresholds: dict[str, float] = Field(
        default_factory=lambda: {
            "impossible_travel_speed_kmh": 900,
            "geo_anomaly_distance_km": 300,
            "velocity_events_last_10m": 6,
            "failed_attempts_last_15m": 3,
            "behavior_deviation": 0.70,
            "sensitive_action_burst_count": 3,
            "device_churn_last_24h": 3,
            "distinct_ips_last_1h": 4,
            "distinct_network_types_last_1h": 3,
            "vpn_switch_count_last_1h": 2,
        }
    )

    decision_ranges: DecisionRanges = Field(default_factory=DecisionRanges)


@lru_cache
def get_policy() -> PolicyConfig:
    return PolicyConfig()