from pydantic import BaseModel

from app.models.hybrid import HybridEvaluationResult
from app.models.response import RiskEvaluateResponse


class ComparisonDelta(BaseModel):
    score_difference: int
    decision_changed: bool
    risk_level_changed: bool


class RiskComparisonResponse(BaseModel):
    v1_rules_only: RiskEvaluateResponse
    v2_hybrid: HybridEvaluationResult
    delta: ComparisonDelta