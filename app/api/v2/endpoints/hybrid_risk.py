from fastapi import APIRouter, Request, Security
from loguru import logger

from app.core.rate_limit import limiter
from app.core.security import verify_api_key
from app.models.hybrid import HybridEvaluationResult
from app.models.request import RiskEvaluateRequest
from app.services.hybrid_scoring import evaluate_hybrid_risk

router = APIRouter()


@router.post(
    "/v2/risk/evaluate-hybrid",
    response_model=HybridEvaluationResult,
    tags=["Risk v2"],
)
@limiter.limit("10/minute")
def evaluate_hybrid(
    request: Request,
    payload: RiskEvaluateRequest,
    api_key: str = Security(verify_api_key),
) -> HybridEvaluationResult:
    logger.info(
        f"Evaluating HYBRID risk for user_id={payload.user_id}, event_type={payload.event_type}"
    )

    result = evaluate_hybrid_risk(payload)

    logger.info(
        f"Hybrid result: rules_score={result.rules_score}, "
        f"ml_score={result.ml_score}, "
        f"final_score={result.final_score}, "
        f"fusion_strategy={result.fusion_strategy}, "
        f"fallback_used={result.fallback_used}, "
        f"engine_version={result.engine_version}"
    )

    return result