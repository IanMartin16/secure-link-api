from pathlib import Path

from ml.scripts.build_dataset import build_dataset, DATASET_COLUMNS


def test_build_dataset_creates_csv(tmp_path: Path):
    records = [
        {
            "event_type": "login",
            "current_hour": 3,
            "is_sensitive_event": 1,
            "rules_score": 80,
            "label_suspicious": 1,
        },
        {
            "event_type": "password_reset",
            "current_hour": 14,
            "is_sensitive_event": 1,
            "rules_score": 20,
            "label_suspicious": 0,
        },
    ]

    output_file = tmp_path / "test_dataset.csv"
    result = build_dataset(records, output_file)

    assert result.exists()

    content = result.read_text(encoding="utf-8")
    header = content.splitlines()[0]

    for column in DATASET_COLUMNS:
        assert column in header