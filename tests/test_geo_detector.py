from datetime import datetime, timezone

from app.models.request import GeoInfo, HistoryInfo, RiskEvaluateRequest
from app.services.detectors.geo import evaluate_geo_signals


def test_geo_anomaly_detected():
    payload = RiskEvaluateRequest(
        event_type="login",
        timestamp=datetime(2026, 3, 21, 18, 0, 0, tzinfo=timezone.utc),
        user_id="usr_002",
        ip="201.111.10.20",
        geo=GeoInfo(
            country="MX",
            city="Monterrey",
            latitude=25.6866,
            longitude=-100.3161,
        ),
        history=HistoryInfo(
            previous_login_at=datetime(2026, 3, 21, 14, 0, 0, tzinfo=timezone.utc),
            previous_geo=GeoInfo(
                country="MX",
                city="CDMX",
                latitude=19.4326,
                longitude=-99.1332,
            ),
            recent_event_types=[],
        ),
    )

    score, reasons = evaluate_geo_signals(payload)

    assert "geo_anomaly_detected" in reasons
    assert score >= 18