"""Train a URL text baseline from an explicitly sourced CSV; no dataset is bundled."""
import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

SEED = 41


def load_data(path):
    frame = pd.read_csv(path, usecols=["url", "label"])
    frame = frame.dropna(subset=["url", "label"])
    frame["url"] = frame["url"].astype(str).str.strip()
    labels = frame["label"].astype(str).str.strip().str.lower().map({
        "0": 0, "benign": 0, "legitimate": 0, "1": 1, "phishing": 1, "malicious": 1,
    })
    frame["label"] = labels
    frame = frame.dropna(subset=["label"])
    frame = frame[frame["url"].str.len().between(1, 4096)]
    frame = frame.drop_duplicates(subset=["url"]).reset_index(drop=True)
    if frame["label"].nunique() != 2 or frame["label"].value_counts().min() < 2:
        raise ValueError("Dataset must contain at least two unique URLs for each of the two labels.")
    frame["label"] = frame["label"].astype(int)
    return frame


def train(dataset, output, metadata_path, source):
    random.seed(SEED)
    frame = load_data(dataset)
    train_x, test_x, train_y, test_y = train_test_split(
        frame.url, frame.label, test_size=0.2, random_state=SEED, stratify=frame.label
    )
    model = Pipeline([
        ("features", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2, max_features=100_000)),
        ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=SEED)),
    ])
    model.fit(train_x, train_y)
    predicted = model.predict(test_x)
    cm = confusion_matrix(test_y, predicted, labels=[0, 1])
    precision, recall, f1, _ = precision_recall_fscore_support(
        test_y, predicted, average="binary", zero_division=0
    )
    metrics = {
        "test_rows": int(len(test_y)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": float(roc_auc_score(test_y, model.predict_proba(test_x)[:, 1])),
        "false_positive_rate": float(cm[0, 1] / max(1, cm[0].sum())),
        "false_negative_rate": float(cm[1, 0] / max(1, cm[1].sum())),
        "confusion_matrix_labels_0_1": cm.tolist(),
    }
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output)
    metadata_path = Path(metadata_path)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps({
        "model_version": "url-tfidf-logreg-v1",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_source_and_license": source,
        "dataset_rows_after_cleaning": int(len(frame)),
        "deduplicated_urls": True,
        "random_seed": SEED,
        "test_split": "stratified random holdout; not time-based",
        "metrics": metrics,
        "limitations": "Metrics are dataset-specific and do not establish real-world detection quality.",
    }, indent=2), encoding="utf-8")
    return metrics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", help="CSV with url,label columns and legally usable data")
    parser.add_argument("--out", default="instance/url_model.joblib")
    parser.add_argument("--metadata", default="instance/model-metadata.json")
    parser.add_argument("--source", required=True, help="Dataset provenance and license reference")
    args = parser.parse_args()
    print(json.dumps(train(args.dataset, args.out, args.metadata, args.source), indent=2))


if __name__ == "__main__":
    main()
