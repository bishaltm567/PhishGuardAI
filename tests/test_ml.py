import csv
import json

import joblib
from ml.train import train
from app.services import ml_classifier


def test_training_is_reproducible_and_writes_metrics(tmp_path):
    dataset = tmp_path / "synthetic.csv"
    with dataset.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["url", "label"])
        for index in range(30):
            writer.writerow([f"https://safe{index}.example.test/page", "benign"])
            writer.writerow([f"http://login-{index}.test/verify?code={index}", "phishing"])
    first_model, second_model = tmp_path / "first.joblib", tmp_path / "second.joblib"
    first_metrics = train(dataset, first_model, tmp_path / "first.json", "synthetic test fixture")
    second_metrics = train(dataset, second_model, tmp_path / "second.json", "synthetic test fixture")
    assert first_metrics == second_metrics
    metadata = json.loads((tmp_path / "first.json").read_text(encoding="utf-8"))
    assert metadata["random_seed"] == 41
    assert metadata["dataset_rows_after_cleaning"] == 60
    assert joblib.load(first_model).predict(["https://safe.example.test"])[0] in (0, 1)


def test_missing_model_falls_back_without_prediction(monkeypatch, tmp_path):
    monkeypatch.setattr(ml_classifier, "MODEL_PATH", tmp_path / "missing.joblib")
    assert ml_classifier.model_status() == "Not trained"
    assert ml_classifier.classify_url("https://example.test") == {
        "available": False, "status": "Model not trained"
    }
