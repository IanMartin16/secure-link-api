from math import asin, cos, radians, sin, sqrt

from app.core.policy import get_policy
from app.models.request import RiskEvaluateRequest


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius = 6371.0

    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)

    a = (
        sin(dlat / 2) ** 2
        + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    )
    a = max(0.0, min(a, 1.0))
    c = 2 * asin(sqrt(a))
    return radius * c


def get_distance_km(payload: RiskEvaluateRequest) -> float | None:
    if not payload.geo or not payload.history or not payload.history.previous_geo:
        return None

    current_geo = payload.geo
    previous_geo = payload.history.previous_geo

    required_values = [
        current_geo.latitude,
        current_geo.longitude,
        previous_geo.latitude,
        previous_geo.longitude,
    ]

    if any(value is None for value in required_values):
        return None

    return _haversine_km(
        previous_geo.latitude,
        previous_geo.longitude,
        current_geo.latitude,
        current_geo.longitude,
    )


def get_country_changed_flag(payload: RiskEvaluateRequest) -> int:
    if not payload.geo or not payload.history or not payload.history.previous_geo:
        return 0

    current_country = payload.geo.country
    previous_country = payload.history.previous_geo.country

    if current_country and previous_country and current_country != previous_country:
        return 1

    return 0


def get_impossible_travel_flag(payload: RiskEvaluateRequest) -> int:
    if not payload.history or not payload.history.previous_login_at:
        return 0

    policy = get_policy()
    distance_km = get_distance_km(payload)
    if distance_km is None:
        return 0

    delta_hours = (payload.timestamp - payload.history.previous_login_at).total_seconds() / 3600
    if delta_hours <= 0:
        return 0

    speed_kmh = distance_km / delta_hours
    return 1 if speed_kmh > policy.thresholds["impossible_travel_speed_kmh"] else 0


def get_geo_anomaly_flag(payload: RiskEvaluateRequest) -> int:
    if get_impossible_travel_flag(payload):
        return 0

    policy = get_policy()
    distance_km = get_distance_km(payload)
    if distance_km is None:
        return 0

    return 1 if distance_km >= policy.thresholds["geo_anomaly_distance_km"] else 0


def evaluate_geo_signals(payload: RiskEvaluateRequest) -> tuple[int, list[str]]:
    policy = get_policy()
    score = 0
    reasons: list[str] = []

    if get_country_changed_flag(payload):
        score += policy.rule_weights["new_country_detected"]
        reasons.append("new_country_detected")

    if get_impossible_travel_flag(payload):
        score += policy.rule_weights["impossible_travel_detected"]
        reasons.append("impossible_travel_detected")
    elif get_geo_anomaly_flag(payload):
        score += policy.rule_weights["geo_anomaly_detected"]
        reasons.append("geo_anomaly_detected")

    return score, reasons