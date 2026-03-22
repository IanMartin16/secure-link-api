from typing import List, Literal
from pydantic import BaseModel


DecisionType = Literal["allow", "review", "challenge", "block"]
RiskLevelType = Literal["low", "medium", "high", "critical"]


class RiskEvaluateResponse(BaseModel):
    request_id: str
    rules_score: int
    final_score: int
    risk_level: RiskLevelType
    decision: DecisionType
    reasons: List[str]
    recommended_action: str
    engine_version: str = "rules-v1.2"