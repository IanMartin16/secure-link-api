from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, ConfigDict


class GeoInfo(BaseModel):
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class DeviceInfo(BaseModel):
    device_id: Optional[str] = None
    is_new_device: bool = False


class NetworkInfo(BaseModel):
    vpn_detected: bool = False
    proxy_detected: bool = False
    tor_detected: bool = False


class BehaviorInfo(BaseModel):
    failed_attempts_last_15m: int = 0
    hourly_pattern_deviation: float = Field(default=0.0, ge=0.0, le=1.0)
    events_last_10m: int = 0
    normal_login_hour_start: int = Field(default=6, ge=0, le=23)
    normal_login_hour_end: int = Field(default=22, ge=0, le=23)


class HistoryInfo(BaseModel):
    previous_login_at: Optional[datetime] = None
    previous_geo: Optional[GeoInfo] = None
    recent_event_types: list[str] = Field(default_factory=list)
    new_devices_last_24h: int = 0
    distinct_ips_last_1h: int = 0
    distinct_network_types_last_1h: int = 0
    vpn_switch_count_last_1h: int = 0


class RiskEvaluateRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "event_type": "login",
                "timestamp": "2026-03-21T03:15:00Z",
                "user_id": "usr_001",
                "ip": "189.123.45.67",
                "device": {
                    "device_id": "dev_abc123",
                    "is_new_device": True
                },
                "behavior": {
                    "failed_attempts_last_15m": 0,
                    "hourly_pattern_deviation": 0.75,
                    "events_last_10m": 7,
                    "normal_login_hour_start": 6,
                    "normal_login_hour_end": 22
                },
                "history": {
                    "recent_event_types": ["password_reset"],
                    "new_devices_last_24h": 2,
                    "distinct_ips_last_1h": 4,
                    "distinct_network_types_last_1h": 2,
                    "vpn_switch_count_last_1h": 1
                }
            }
        }
    )

    event_type: str
    timestamp: datetime
    user_id: str
    ip: str
    geo: Optional[GeoInfo] = None
    device: Optional[DeviceInfo] = None
    network: Optional[NetworkInfo] = None
    behavior: Optional[BehaviorInfo] = None
    history: Optional[HistoryInfo] = None