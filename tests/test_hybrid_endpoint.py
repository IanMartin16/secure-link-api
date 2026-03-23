from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_hybrid_endpoint_requires_api_key():
    payload = {
        "event_type": "login",
        "timestamp": "2026-03-21T03:15:00Z",
        "user_id": "usr_test_hybrid",
        "ip": "189.123.45.67"
    }

    response = client.post("/v2/risk/evaluate-hybrid", json=payload)

    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == "missing_api_key"


def test_hybrid_endpoint_success():
    payload = {
        "event_type": "login",
        "timestamp": "2026-03-21T03:15:00Z",
        "user_id": "usr_test_hybrid",
        "ip": "189.123.45.67",
        "device": {
            "device_id": "dev_001",
            "is_new_device": True
        },
        "network": {
            "vpn_detected": True,
            "proxy_detected": False,
            "tor_detected": False
        },
        "behavior": {
            "failed_attempts_last_15m": 2,
            "hourly_pattern_deviation": 0.75,
            "events_last_10m": 7,
            "normal_login_hour_start": 6,
            "normal_login_hour_end": 22
        },
        "history": {
            "recent_event_types": ["password_reset", "login", "email_change"],
            "new_devices_last_24h": 3,
            "distinct_ips_last_1h": 4,
            "distinct_network_types_last_1h": 2,
            "vpn_switch_count_last_1h": 1
        }
    }

    response = client.post(
        "/v2/risk/evaluate-hybrid",
        json=payload,
        headers={"X-API-Key": "securelink-dev-key-123"},
    )

    assert response.status_code == 200
    body = response.json()

    assert "rules_score" in body
    assert "ml_score" in body
    assert "final_score" in body
    assert "fusion_strategy" in body
    assert "fallback_used" in body
    assert "engine_version" in body