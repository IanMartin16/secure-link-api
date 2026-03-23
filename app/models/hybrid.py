from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict


DecisionType = Literal["allow", "review", "challenge", "block"]
RiskLevelType = Literal["low", "medium", "high", "critical"]


class HybridEvaluationResult(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    rules_score: int
    ml_score: Optional[int] = None
    final_score: int
    risk_level: RiskLevelType
    decision: DecisionType
    reasons: List[str]
    fusion_strategy: str
    fallback_used: bool
    model_version: Optional[str] = None
    engine_version: str