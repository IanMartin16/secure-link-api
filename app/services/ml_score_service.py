from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import pandas as pd


MODEL_VERSION = "xgb-001"
PIPELINE_FILENAME = "xgb_secure_link_v2_alpha_pipeline.joblib"


def _get_project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _get_pipeline_path() -> Path:
    return _get_project_root() / "ml" / "models" / PIPELINE_FILENAME


def load_pipeline(pipeline_path: Path | None = None):
    path = pipeline_path or _get_pipeline_path()

    if not path.exists():
        raise FileNotFoundError(f"ML pipeline not found: {path}")

    return joblib.load(path)


def predict_ml_score(
    feature_record: dict[str, Any],
    pipeline=None,
) -> dict[str, Any]:
    model_pipeline = pipeline or load_pipeline()

    df = pd.DataFrame([feature_record])
    prob = float(model_pipeline.predict_proba(df)[0][1])
    ml_score = int(round(prob * 100))

    return {
        "ml_score": ml_score,
        "ml_probability": prob,
        "model_version": MODEL_VERSION,
        "ml_available": True,
    }


def get_ml_model_metadata() -> dict[str, Any]:
    return {
        "model_version": MODEL_VERSION,
        "pipeline_filename": PIPELINE_FILENAME,
    }