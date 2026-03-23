from datetime import datetime, timezone

from app.models.request import HistoryInfo, RiskEvaluateRequest
from app.services.aggregations import build_score_breakdown


def test_recent_sensitive_event_count():
    payload = RiskEvaluateRequest(
        event_type="login",
        timestamp=datetime(2026, 3, 21, 3, 15, 0, tzinfo=timezone.utc),
        user_id="usr_100",
        ip="189.123.45.67",
        history=HistoryInfo(
            recent_event_types=[
                "password_reset",
                "login",
                "email_change",
                "unknown_event",
            ]
        ),
    )

    breakdown, reasons = build_score_breakdown(payload)

    assert breakdown.recent_sensitive_event_count == 3