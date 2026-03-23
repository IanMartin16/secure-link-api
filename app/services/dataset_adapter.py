from app.models.request import RiskEvaluateRequest
from app.services.feature_builder import build_feature_record
from app.services.scoring import evaluate_risk


def build_dataset_row_from_payload(
    payload: RiskEvaluateRequest,
    label_suspicious: int | None = None,
) -> dict:
    rules_score, final_score, reasons, risk_level, decision, breakdown = evaluate_risk(payload)

    record = build_feature_record(
        payload=payload,
        breakdown=breakdown,
        rules_score=rules_score,
    )

    record["final_score"] = final_score
    record["risk_level"] = risk_level
    record["decision"] = decision
    record["label_suspicious"] = label_suspicious if label_suspicious is not None else 0

    return record