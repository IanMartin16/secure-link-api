from uuid import uuid4

from fastapi import APIRouter, Request, Security
from loguru import logger

from app.core.rate_limit import limiter
from app.core.security import verify_api_key
from app.models.request import RiskEvaluateRequest
from app.models.response import RiskEvaluateResponse
from app.services.scoring import evaluate_risk

router = APIRouter()


@router.post(
    "/v1/risk/evaluate",
    response_model=RiskEvaluateResponse,
    tags=["Risk"],
)
@limiter.limit("10/minute")
def evaluate(
    request: Request,
    payload: RiskEvaluateRequest,
    api_key: str = Security(verify_api_key),
) -> RiskEvaluateResponse:
    logger.info(
        f"Evaluating risk for user_id={payload.user_id}, event_type={payload.event_type}"
    )

    rules_score, final_score, reasons, risk_level, decision = evaluate_risk(payload)

    recommended_action_map = {
        "allow": "none",
        "review": "log_only",
        "challenge": "require_mfa",
        "block": "require_mfa_or_block",
    }

    return RiskEvaluateResponse(
        request_id=f"rsk_{uuid4().hex[:10]}",
        rules_score=rules_score,
        final_score=final_score,
        risk_level=risk_level,
        decision=decision,
        reasons=reasons,
        recommended_action=recommended_action_map[decision],
        engine_version="rules-v1.2",
    )