from datetime import datetime
from typing import Optional

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
    model_validator,
)


class GeoInfo(BaseModel):
    country: str | None = None
    city: str | None = Field(default=None, max_length=128)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)

    @field_validator("country")
    @classmethod
    def normalize_country(cls, value: str | None) -> str | None:
        if value is None:
            return None

        normalized = value.strip().upper()

        if len(normalized) != 2 or not normalized.isalpha():
            raise ValueError(
                "country must be an ISO 3166-1 alpha-2 code"
            )

        return normalized

    @model_validator(mode="after")
    def validate_coordinates_pair(self):
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError(
                "latitude and longitude must be provided together"
            )

        return self


class DeviceInfo(BaseModel):
    device_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
    )
    is_new_device: bool = False


class NetworkInfo(BaseModel):
    vpn_detected: bool = False
    proxy_detected: bool = False
    tor_detected: bool = False


class BehaviorInfo(BaseModel):
    failed_attempts_last_15m: int = Field(default=0, ge=0)
    hourly_pattern_deviation: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )
    events_last_10m: int = Field(default=0, ge=0)
    normal_login_hour_start: int = Field(default=6, ge=0, le=23)
    normal_login_hour_end: int = Field(default=22, ge=0, le=23)


class HistoryInfo(BaseModel):
    previous_login_at: AwareDatetime | None = None
    previous_geo: GeoInfo | None = None
    recent_event_types: list[str] = Field(
        default_factory=list,
        max_length=100,
    )
    new_devices_last_24h: int = Field(default=0, ge=0)
    distinct_ips_last_1h: int = Field(default=0, ge=0)
    distinct_network_types_last_1h: int = Field(default=0, ge=0)
    vpn_switch_count_last_1h: int = Field(default=0, ge=0)

    @field_validator("recent_event_types")
    @classmethod
    def normalize_recent_events(cls, values: list[str]) -> list[str]:
        normalized = []

        for value in values:
            event = value.strip().lower()
            if not event:
                raise ValueError(
                    "recent_event_types cannot contain empty values"
                )
            normalized.append(event)

        return normalized


class RiskEvaluateRequest(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "event_type": "login",
                "timestamp": "2026-03-21T03:15:00Z",
                "user_id": "usr_001",
                "ip": "189.123.45.67",
                "device": {
                    "device_id": "dev_abc123",
                    "is_new_device": True,
                },
                "behavior": {
                    "failed_attempts_last_15m": 0,
                    "hourly_pattern_deviation": 0.75,
                    "events_last_10m": 7,
                    "normal_login_hour_start": 6,
                    "normal_login_hour_end": 22,
                },
                "history": {
                    "recent_event_types": ["password_reset"],
                    "new_devices_last_24h": 2,
                    "distinct_ips_last_1h": 4,
                    "distinct_network_types_last_1h": 2,
                    "vpn_switch_count_last_1h": 1,
                },
            }
        },
    )

    event_type: str = Field(min_length=1, max_length=64)
    timestamp: AwareDatetime
    user_id: str = Field(min_length=1, max_length=128)
    ip: IPvAnyAddress
    geo: GeoInfo | None = None
    device: DeviceInfo | None = None
    network: NetworkInfo | None = None
    behavior: BehaviorInfo | None = None
    history: HistoryInfo | None = None

    @field_validator("event_type")
    @classmethod
    def normalize_event_type(cls, value: str) -> str:
        return value.strip().lower()

    @model_validator(mode="after")
    def validate_timeline(self):
        if (
            self.history
            and self.history.previous_login_at
            and self.history.previous_login_at > self.timestamp
        ):
            raise ValueError(
                "history.previous_login_at cannot be later than timestamp"
            )

        return self