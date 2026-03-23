from app.models.internal import ScoreBreakdown
from app.models.request import RiskEvaluateRequest
from app.services.detectors.behavior import evaluate_behavior_signals
from app.services.detectors.device import evaluate_device_signals
from app.services.detectors.geo import (
    evaluate_geo_signals,
    get_country_changed_flag,
    get_distance_km,
)
from app.services.detectors.network import evaluate_network_signals
from app.services.detectors.sequence import (
    SENSITIVE_EVENT_TYPES,
    evaluate_sequence_signals,
)


def _count_recent_sensitive_events(payload: RiskEvaluateRequest) -> int:
    if not payload.history:
        return 0

    recent = payload.history.recent_event_types or []
    return sum(1 for event in recent if event in SENSITIVE_EVENT_TYPES)


def build_score_breakdown(payload: RiskEvaluateRequest) -> tuple[ScoreBreakdown, list[str]]:
    device_subscore, device_reasons = evaluate_device_signals(payload)
    network_subscore, network_reasons = evaluate_network_signals(payload)
    behavior_subscore, behavior_reasons = evaluate_behavior_signals(payload)
    geo_subscore, geo_reasons = evaluate_geo_signals(payload)
    sequence_subscore, sequence_reasons = evaluate_sequence_signals(payload)

    reasons = (
        device_reasons
        + network_reasons
        + behavior_reasons
        + geo_reasons
        + sequence_reasons
    )

    distance_km = get_distance_km(payload)
    country_changed_flag = get_country_changed_flag(payload)

    breakdown = ScoreBreakdown(
        device_subscore=device_subscore,
        network_subscore=network_subscore,
        behavior_subscore=behavior_subscore,
        geo_subscore=geo_subscore,
        sequence_subscore=sequence_subscore,
        active_signal_count=len(reasons),
        recent_sensitive_event_count=_count_recent_sensitive_events(payload),
        country_changed_flag=country_changed_flag,
        distance_from_previous_km=round(distance_km, 2) if distance_km is not None else 0.0,
    )

    return breakdown, reasons