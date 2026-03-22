from datetime import datetime, timezone

from app.models.request import HistoryInfo, RiskEvaluateRequest
from app.services.detectors.sequence import evaluate_sequence_signals


def test_sensitive_action_burst_detected():
    payload = RiskEvaluateRequest(
        event_type="phone_change",
        timestamp=datetime(2026, 3, 21, 4, 10, 0, tzinfo=timezone.utc),
        user_id="usr_010",
        ip="189.123.45.67",
        history=HistoryInfo(
            recent_event_types=[
                "password_reset",
                "login",
                "email_change",
            ]
        ),
    )

    score, reasons = evaluate_sequence_signals(payload)

    assert "sensitive_action_burst" in reasons
    assert score >= 22