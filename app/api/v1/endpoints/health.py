from datetime import datetime, timezone

from fastapi import APIRouter, Response, status

from app.core.config import settings
from app.core.runtime import get_uptime_seconds
from app.models.health import (
    HealthCheck,
    HealthResponse,
    LiveResponse,
    ReadyResponse,
    ServiceInfo,
)


router = APIRouter(tags=["Health"])


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def configuration_is_valid() -> bool:
    return bool(
        settings.APP_VERSION
        and settings.ENVIRONMENT
    )


@router.get(
    "/health",
    response_model=dict[str, str],
    include_in_schema=False,
)
def legacy_health() -> dict[str, str]:
    return {"status": "ok"}


@router.get(
    "/api/health",
    response_model=HealthResponse,
    response_model_exclude_none=True,
)
def health(response: Response) -> HealthResponse:
    configuration_ok = configuration_is_valid()
    service_ready = configuration_ok

    response.status_code = (
        status.HTTP_200_OK
        if service_ready
        else status.HTTP_503_SERVICE_UNAVAILABLE
    )

    return HealthResponse(
        service=ServiceInfo(
            id="secure-link",
            name="Secure_Link",
            version=settings.APP_VERSION,
            environment=settings.ENVIRONMENT,
            stack="fastapi",
        ),
        status="operational" if service_ready else "degraded",
        readiness="ready" if service_ready else "not_ready",
        timestamp=utc_now(),
        uptime_seconds=get_uptime_seconds(),
        checks={
            "application": HealthCheck(
                status="operational",
            ),
            "configuration": HealthCheck(
                status=(
                    "operational"
                    if configuration_ok
                    else "degraded"
                ),
                message=(
                    None
                    if configuration_ok
                    else "Required application configuration is incomplete"
                ),
            ),
        },
    )


@router.get(
    "/api/health/live",
    response_model=LiveResponse,
)
def live() -> LiveResponse:
    return LiveResponse(
        service_id="secure-link",
        status="alive",
        timestamp=utc_now(),
    )


@router.get(
    "/api/health/ready",
    response_model=ReadyResponse,
    response_model_exclude_none=True,
)
def ready(response: Response) -> ReadyResponse:
    configuration_ok = configuration_is_valid()

    response.status_code = (
        status.HTTP_200_OK
        if configuration_ok
        else status.HTTP_503_SERVICE_UNAVAILABLE
    )

    return ReadyResponse(
        service_id="secure-link",
        status="ready" if configuration_ok else "not_ready",
        timestamp=utc_now(),
        checks={
            "configuration": HealthCheck(
                status=(
                    "operational"
                    if configuration_ok
                    else "degraded"
                ),
                message=(
                    None
                    if configuration_ok
                    else "Required application configuration is incomplete"
                ),
            ),
        },
    )