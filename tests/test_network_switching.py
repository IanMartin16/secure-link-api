from datetime import datetime, timezone

from app.models.request import HistoryInfo, NetworkInfo, RiskEvaluateRequest
from app.services.detectors.network import evaluate_network_signals


def test_network_switching_anomaly_detected():
    payload = RiskEvaluateRequest(
        event_type="login",
        timestamp=datetime(2026, 3, 21, 19, 20, 0, tzinfo=timezone.utc),
        user_id="usr_030",
        ip="189.123.45.67",
        network=NetworkInfo(
            vpn_detected=False,
            proxy_detected=False,
            tor_detected=False,
        ),
        history=HistoryInfo(
            recent_event_types=["login"],
            new_devices_last_24h=1,
            distinct_ips_last_1h=4,
            distinct_network_types_last_1h=2,
            vpn_switch_count_last_1h=1,
        ),
    )

    score, reasons = evaluate_network_signals(payload)

    assert "network_switching_anomaly" in reasons
    assert score >= 16