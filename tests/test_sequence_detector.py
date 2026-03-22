from datetime import datetime, timezone

from app.models.request import HistoryInfo, RiskEvaluateRequest
from app.services.detectors.sequence import evaluate_sequence_signals


def test_event_sequence_anomaly_detected():
    payload = RiskEvaluateRequest(
        event_type="login",
        timestamp=datetime(2026, 3, 21, 3, 15, 0, tzinfo=timezone.utc),
        user_id="usr_003",
        ip="189.123.45.67",
        history=HistoryInfo(
            recent_event_types=["password_reset"]
        ),
    )

    score, reasons = evaluate_sequence_signals(payload)

    assert score == 20
    assert "event_sequence_anomaly" in reasons