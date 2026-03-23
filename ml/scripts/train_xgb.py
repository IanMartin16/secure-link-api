from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from xgboost import XGBClassifier


TARGET_COLUMN = "label_suspicious"
CATEGORICAL_COLUMNS = ["event_type"]
DROP_COLUMNS = []


def load_dataset(dataset_path: Path) -> pd.DataFrame:
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    df = pd.read_csv(dataset_path)
    if TARGET_COLUMN not in df.columns:
        raise ValueError(f"Missing target column: {TARGET_COLUMN}")

    return df


def build_pipeline(numeric_columns: list[str], categorical_columns: list[str]) -> Pipeline:
    numeric_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="constant", fill_value=0)),
        ]
    )

    categorical_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, numeric_columns),
            ("cat", categorical_transformer, categorical_columns),
        ]
    )

    model = XGBClassifier(
        n_estimators=150,
        max_depth=4,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=4,
        tree_method="hist",
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", model),
        ]
    )

    return pipeline


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]
    dataset_path = project_root / "ml" / "datasets" / "secure_link_v2_alpha.csv"
    model_output_path = project_root / "ml" / "models" / "xgb_secure_link_v2_alpha.json"
    pipeline_output_path = project_root / "ml" / "models" / "xgb_secure_link_v2_alpha_pipeline.joblib"

    df = load_dataset(dataset_path)

    if len(df) < 10:
        raise ValueError(
            "Dataset too small for training. Add more rows before running train_xgb.py."
        )

    X = df.drop(columns=[TARGET_COLUMN, *DROP_COLUMNS], errors="ignore")
    y = df[TARGET_COLUMN]

    class_counts = y.value_counts()
    if class_counts.min() < 2:
        raise ValueError(
            "Each class in label_suspicious needs at least 2 rows for stratified split."
        )

    categorical_columns = [col for col in CATEGORICAL_COLUMNS if col in X.columns]
    numeric_columns = [col for col in X.columns if col not in categorical_columns]

    if y.nunique() < 2:
        raise ValueError(
            "The dataset needs at least two classes in label_suspicious to train a classifier."
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.30,
        random_state=42,
        stratify=y,
    )

    pipeline = build_pipeline(numeric_columns, categorical_columns)
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_prob)

    print("=== Secure_Link XGBoost Training Summary ===")
    print(f"Rows total: {len(df)}")
    print(f"Train rows: {len(X_train)}")
    print(f"Test rows : {len(X_test)}")
    print()
    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"ROC-AUC  : {roc_auc:.4f}")
    print()
    print("Classification report:")
    print(classification_report(y_test, y_pred, zero_division=0))

    model_output_path.parent.mkdir(parents=True, exist_ok=True)

    model = pipeline.named_steps["model"]
    model.save_model(model_output_path)
    joblib.dump(pipeline, pipeline_output_path)

    print(f"Model saved at: {model_output_path}")
    print(f"Pipeline saved at: {pipeline_output_path}")


if __name__ == "__main__":
    main()