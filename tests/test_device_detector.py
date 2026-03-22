from datetime import datetime, timezone

from app.models.request import DeviceInfo, RiskEvaluateRequest
from app.services.detectors.device import evaluate_device_signals


def test_new_device_detected():
    payload = RiskEvaluateRequest(
        event_type="login",
        timestamp=datetime.now(timezone.utc),
        user_id="usr_001",
        ip="189.123.45.67",
        device=DeviceInfo(device_id="dev_001", is_new_device=True),
    )

    score, reasons = evaluate_device_signals(payload)

    assert score == 20
    assert "new_device_detected" in reasons