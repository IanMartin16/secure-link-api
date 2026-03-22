# Secure_Link API

Secure_Link is an API-first risk intelligence service for sensitive account security events.

## Public capability
**Risk Signals**

Risk Signals evaluates contextual risk before the client system makes a final decision.

## Current version
**v1.0.0**

## MVP scope
- Contextual risk evaluation
- Account security events
- Explainable scoring
- API key protection
- FastAPI + Swagger docs

## Supported endpoints
- `GET /health`
- `GET /v1/capabilities`
- `POST /v1/risk/evaluate`

## Authentication
Protected endpoints require:

- Header: `X-API-Key`

Example:

```http
X-API-Key: securelink-dev-key-123