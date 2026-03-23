from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_v2_capabilities():
    response = client.get("/v2/capabilities")

    assert response.status_code == 200
    body = response.json()

    assert body["product"] == "Secure_Link"
    assert body["engine"] == "hybrid-v2"
    assert "rules_score" in body["score_components"]
    assert "ml_score" in body["score_components"]
    assert "final_score" in body["score_components"]
    assert body["model"]["model_version"] == "xgb-001"
    assert body["fusion"]["strategy"] == "weighted_rules_first"