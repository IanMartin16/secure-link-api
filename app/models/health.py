from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


HealthStatus = Literal["operational", "degraded"]
ReadinessStatus = Literal["ready", "not_ready"]
CheckStatus = Literal["operational", "degraded"]


class HealthCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: CheckStatus
    message: str | None = None


class ServiceInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    version: str
    environment: str
    stack: str


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal["health.v1"] = "health.v1"
    service: ServiceInfo
    status: HealthStatus
    readiness: ReadinessStatus
    timestamp: datetime
    uptime_seconds: int
    checks: dict[str, HealthCheck]


class LiveResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal["health.v1"] = "health.v1"
    service_id: str
    status: Literal["alive"]
    timestamp: datetime


class ReadyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal["health.v1"] = "health.v1"
    service_id: str
    status: ReadinessStatus
    timestamp: datetime
    checks: dict[str, HealthCheck]