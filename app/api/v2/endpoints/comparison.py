from fastapi import APIRouter, Request, Security
from loguru import logger

from app.core.rate_limit import limiter
from app.core.security import verify_api_key
from app.models.comparison import RiskComparisonResponse
from app.models.request import RiskEvaluateRequest
from app.services.comparison_service import compare_v1_vs_v2

router = APIRouter()


@router.post(
    "/v2/risk/compare",
    response_model=RiskComparisonResponse,
    tags=["Risk v2"],
)
@limiter.limit("10/minute")
def compare(
    request: Request,
    payload: RiskEvaluateRequest,
    api_key: str = Security(verify_api_key),
) -> RiskComparisonResponse:
    logger.info(
        f"Comparing v1 vs v2 for user_id={payload.user_id}, event_type={payload.event_type}"
    )
    return compare_v1_vs_v2(payload)