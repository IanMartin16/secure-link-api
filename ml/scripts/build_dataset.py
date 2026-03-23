from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable


DATASET_COLUMNS = [
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
    "label_suspicious",
]


def normalize_record(record: dict) -> dict:
    normalized: dict = {}

    for column in DATASET_COLUMNS:
        if column in record:
            normalized[column] = record[column]
            continue

        if column == "event_type":
            normalized[column] = ""
        elif column in {"hourly_pattern_deviation", "distance_from_previous_km"}:
            normalized[column] = 0.0
        else:
            normalized[column] = 0

    return normalized


def build_dataset(records: Iterable[dict], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    normalized_records = [normalize_record(record) for record in records]

    with output_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=DATASET_COLUMNS)
        writer.writeheader()
        writer.writerows(normalized_records)

    return output_path


def demo_records() -> list[dict]:
    records: list[dict] = []

    # Casos normales
    for i in range(15):
        records.append(
            {
                "event_type": "login",
                "current_hour": 9 + (i % 8),
                "is_sensitive_event": 1,
                "is_new_device": 0,
                "vpn_detected": 0,
                "proxy_detected": 0,
                "tor_detected": 0,
                "failed_attempts_last_15m": i % 2,
                "hourly_pattern_deviation": round(0.05 + (i % 3) * 0.05, 2),
                "events_last_10m": 1 + (i % 2),
                "new_devices_last_24h": 0,
                "distinct_ips_last_1h": 1,
                "distinct_network_types_last_1h": 1,
                "vpn_switch_count_last_1h": 0,
                "country_changed_flag": 0,
                "distance_from_previous_km": round(2.0 + i * 0.7, 2),
                "impossible_travel_flag": 0,
                "geo_anomaly_flag": 0,
                "event_sequence_anomaly_flag": 0,
                "sensitive_action_burst_flag": 0,
                "device_churn_flag": 0,
                "network_switching_flag": 0,
                "rules_score": 5 + (i % 8),
                "active_signal_count": 1,
                "recent_sensitive_event_count": 1 + (i % 2),
                "device_subscore": 0,
                "network_subscore": 0,
                "behavior_subscore": 5 + (i % 5),
                "geo_subscore": 0,
                "sequence_subscore": 0,
                "label_suspicious": 0,
            }
        )

    # Casos sospechosos moderados
    for i in range(10):
        records.append(
            {
                "event_type": "login" if i % 2 == 0 else "password_reset",
                "current_hour": 1 + (i % 4),
                "is_sensitive_event": 1,
                "is_new_device": 1,
                "vpn_detected": 1 if i % 2 == 0 else 0,
                "proxy_detected": 0,
                "tor_detected": 0,
                "failed_attempts_last_15m": 2 + (i % 3),
                "hourly_pattern_deviation": round(0.65 + (i % 3) * 0.08, 2),
                "events_last_10m": 4 + (i % 3),
                "new_devices_last_24h": 2 + (i % 2),
                "distinct_ips_last_1h": 3 + (i % 2),
                "distinct_network_types_last_1h": 2,
                "vpn_switch_count_last_1h": 1,
                "country_changed_flag": 0 if i % 2 == 0 else 1,
                "distance_from_previous_km": round(120.0 + i * 35.0, 2),
                "impossible_travel_flag": 0,
                "geo_anomaly_flag": 1 if i % 3 == 0 else 0,
                "event_sequence_anomaly_flag": 1 if i % 2 == 0 else 0,
                "sensitive_action_burst_flag": 1 if i % 3 != 0 else 0,
                "device_churn_flag": 1 if i % 2 == 1 else 0,
                "network_switching_flag": 1 if i % 3 == 0 else 0,
                "rules_score": 45 + i,
                "active_signal_count": 3 + (i % 3),
                "recent_sensitive_event_count": 2 + (i % 3),
                "device_subscore": 20 + (i % 2) * 18,
                "network_subscore": 15 if i % 2 == 0 else 16,
                "behavior_subscore": 20 + (i % 3) * 10,
                "geo_subscore": 18 if i % 3 == 0 else 0,
                "sequence_subscore": 20 if i % 2 == 0 else 22,
                "label_suspicious": 1,
            }
        )

    # Casos críticos
    for i in range(10):
        records.append(
            {
                "event_type": "device_enrollment" if i % 2 == 0 else "login",
                "current_hour": i % 4,
                "is_sensitive_event": 1,
                "is_new_device": 1,
                "vpn_detected": 1,
                "proxy_detected": 1 if i % 2 == 0 else 0,
                "tor_detected": 1 if i % 3 == 0 else 0,
                "failed_attempts_last_15m": 4 + (i % 3),
                "hourly_pattern_deviation": round(0.80 + (i % 2) * 0.10, 2),
                "events_last_10m": 6 + (i % 4),
                "new_devices_last_24h": 3 + (i % 2),
                "distinct_ips_last_1h": 4 + (i % 2),
                "distinct_network_types_last_1h": 3,
                "vpn_switch_count_last_1h": 2 + (i % 2),
                "country_changed_flag": 1,
                "distance_from_previous_km": round(900.0 + i * 150.0, 2),
                "impossible_travel_flag": 1 if i % 2 == 0 else 0,
                "geo_anomaly_flag": 0 if i % 2 == 0 else 1,
                "event_sequence_anomaly_flag": 1,
                "sensitive_action_burst_flag": 1,
                "device_churn_flag": 1,
                "network_switching_flag": 1,
                "rules_score": 75 + (i % 20),
                "active_signal_count": 6 + (i % 3),
                "recent_sensitive_event_count": 3 + (i % 2),
                "device_subscore": 38,
                "network_subscore": 31 + (i % 2) * 10,
                "behavior_subscore": 35,
                "geo_subscore": 40 if i % 2 == 0 else 18,
                "sequence_subscore": 42,
                "label_suspicious": 1,
            }
        )

    return records


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]
    output_path = project_root / "ml" / "datasets" / "secure_link_v2_alpha.csv"

    path = build_dataset(demo_records(), output_path)
    print(f"Dataset created successfully at: {path}")


if __name__ == "__main__":
    main()