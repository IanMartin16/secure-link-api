from typing import Any, Literal

from app.models.request import RiskEvaluateRequest
from app.services.feature_builder import build_feature_record
from app.services.scoring import evaluate_risk


def build_dataset_row_from_payload(
    payload: RiskEvaluateRequest,
    label_suspicious: Literal[0, 1] | None = None,
) -> dict[str, Any]:
    (
        rules_score,
        final_score,
        _reasons,
        risk_level,
        decision,
        breakdown,
    ) = evaluate_risk(payload)

    features = build_feature_record(
        payload=payload,
        breakdown=breakdown,
        rules_score=rules_score,
    )

    return {
        **features,
        "final_score": final_score,
        "risk_level": risk_level,
        "decision": decision,
        "label_suspicious": label_suspicious,
    }