from datetime import datetime, timezone

from app.models.request import DeviceInfo, HistoryInfo, RiskEvaluateRequest
from app.services.detectors.device import evaluate_device_signals


def test_device_churn_detected():
    payload = RiskEvaluateRequest(
        event_type="login",
        timestamp=datetime(2026, 3, 21, 16, 30, 0, tzinfo=timezone.utc),
        user_id="usr_020",
        ip="189.123.45.67",
        device=DeviceInfo(device_id="dev_xyz_999", is_new_device=True),
        history=HistoryInfo(
            recent_event_types=["login"],
            new_devices_last_24h=3,
        ),
    )

    score, reasons = evaluate_device_signals(payload)

    assert "new_device_detected" in reasons
    assert "device_churn_detected" in reasons
    assert score >= 38