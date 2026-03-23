from datetime import datetime, timezone

from app.models.request import GeoInfo, HistoryInfo, RiskEvaluateRequest
from app.services.aggregations import build_score_breakdown


def test_geo_derived_fields():
    payload = RiskEvaluateRequest(
        event_type="login",
        timestamp=datetime(2026, 3, 21, 18, 0, 0, tzinfo=timezone.utc),
        user_id="usr_geo_001",
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
                country="US",
                city="Austin",
                latitude=30.2672,
                longitude=-97.7431,
            ),
            recent_event_types=[],
        ),
    )

    breakdown, reasons = build_score_breakdown(payload)

    assert breakdown.country_changed_flag == 1
    assert breakdown.distance_from_previous_km > 0