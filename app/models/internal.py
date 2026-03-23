from pydantic import BaseModel


class ScoreBreakdown(BaseModel):
    device_subscore: int = 0
    network_subscore: int = 0
    behavior_subscore: int = 0
    geo_subscore: int = 0
    sequence_subscore: int = 0
    active_signal_count: int = 0
    recent_sensitive_event_count: int = 0
    country_changed_flag: int = 0
    distance_from_previous_km: float = 0.0