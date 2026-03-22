from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api.v1.endpoints.capabilities import router as capabilities_router
from app.api.v1.endpoints.health import router as health_router
from app.api.v1.endpoints.risk import router as risk_router
from app.api.v1.endpoints.policy import router as policy_router
from app.core.config import settings
from app.core.exceptions import (
    rate_limit_exception_handler,
    validation_exception_handler,
)
from app.core.logging import configure_logging
from app.core.rate_limit import limiter

configure_logging()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="API-first risk intelligence for sensitive events.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(RateLimitExceeded, rate_limit_exception_handler)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        return JSONResponse(status_code=exc.status_code, content=exc.detail)

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": "http_error",
                "message": str(exc.detail),
                "status": exc.status_code,
            }
        },
    )


app.include_router(health_router)
app.include_router(capabilities_router)
app.include_router(risk_router)
app.include_router(policy_router)