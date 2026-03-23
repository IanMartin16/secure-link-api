# Secure_Link API

Secure_Link is an API-first risk intelligence service for sensitive account security events.

## Public capability
**Risk Signals**

Risk Signals evaluates contextual risk before a client system makes a final decision.

---

## Current architecture

### v1.2
Rules-based configurable risk engine.

### v2.0-alpha
Hybrid risk engine with:
- rules scoring
- ML scoring (XGBoost)
- weighted fusion
- rules-only fallback
- comparison between v1 and v2

---

## Core goals
- suspicious login detection
- account takeover risk evaluation
- challenge likelihood support
- explainable scoring with gradual ML enhancement

---

## Available endpoints

### v1
- `GET /health`
- `GET /v1/capabilities`
- `GET /v1/policy`
- `POST /v1/risk/evaluate`

### v2
- `GET /v2/capabilities`
- `POST /v2/risk/evaluate-hybrid`
- `POST /v2/risk/compare`

---

## Rules engine signals
	•	new_device_detected
	•	vpn_detected
	•	proxy_detected
	•	tor_detected
	•	multiple_recent_failures
	•	behavior_out_of_pattern
	•	new_country_detected
	•	impossible_travel_detected
	•	odd_hours_detected
	•	velocity_abuse_detected
	•	geo_anomaly_detected
	•	event_sequence_anomaly
	•	sensitive_action_burst
	•	device_churn_detected
	•	network_switching_anomaly
---   

## v1 response model
{
  "request_id": "rsk_xxxxx",
  "rules_score": 78,
  "final_score": 78,
  "risk_level": "high",
  "decision": "challenge",
  "reasons": [
    "new_device_detected",
    "device_churn_detected"
  ],
  "recommended_action": "require_mfa",
  "engine_version": "rules-v1.2"
}
---

## v2 response model
{
  "request_id": "rsk_xxxxx",
  "rules_score": 78,
  "final_score": 78,
  "risk_level": "high",
  "decision": "challenge",
  "reasons": [
    "new_device_detected",
    "device_churn_detected"
  ],
  "recommended_action": "require_mfa",
  "engine_version": "rules-v1.2"
}
---

## fallback response model
{
  "rules_score": 78,
  "ml_score": null,
  "final_score": 78,
  "risk_level": "high",
  "decision": "challenge",
  "reasons": [
    "new_device_detected",
    "vpn_detected"
  ],
  "fusion_strategy": "rules_only",
  "fallback_used": true,
  "model_version": null,
  "engine_version": "rules-only-fallback"
}
---

## v2 comparison response

{
  "v1_rules_only": {
    "request_id": "comparison-v1",
    "rules_score": 78,
    "final_score": 78,
    "risk_level": "high",
    "decision": "challenge",
    "reasons": [
      "new_device_detected",
      "device_churn_detected"
    ],
    "recommended_action": "require_mfa",
    "engine_version": "rules-v1.2"
  },
  "v2_hybrid": {
    "rules_score": 78,
    "ml_score": 91,
    "final_score": 82,
    "risk_level": "critical",
    "decision": "block",
    "reasons": [
      "new_device_detected",
      "device_churn_detected",
      "network_switching_anomaly"
    ],
    "fusion_strategy": "weighted_rules_first",
    "fallback_used": false,
    "model_version": "xgb-001",
    "engine_version": "hybrid-v2"
  },
  "delta": {
    "score_difference": 4,
    "decision_changed": true,
    "risk_level_changed": true
  }
}
---

## ML pipeline status
Secure_Link v2 alpha already includes:
	•	feature record builder
	•	dataset adapter
	•	dataset CSV generator
	•	XGBoost training pipeline
	•	serialized pipeline for inference
	•	ML scoring service

Artifacts currently generated:
	•	ml/datasets/secure_link_v2_alpha.csv
	•	ml/models/xgb_secure_link_v2_alpha.json
	•	ml/models/xgb_secure_link_v2_alpha_pipeline.joblib

---

## Roadmap direction

### Closed
	•	v1.2 configurable rules engine
	•	v2.0-alpha hybrid scoring foundation

### Next likely steps
	•	observability for hybrid comparisons
	•	model iteration and retraining flow
	•	improved dataset generation from real evaluations
	•	future ML tuning and fusion refinements
---    

## Authentication
Protected endpoints require:

`X-API-Key`

Example:

```http
X-API-Key: securelink-dev-key-123
 