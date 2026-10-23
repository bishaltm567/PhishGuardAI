"""Re-evaluate a saved local model on a separately supplied labeled CSV."""
import argparse
import json

import joblib
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("model")
    parser.add_argument("dataset", help="Held-out CSV with url,label columns")
    args = parser.parse_args()
    frame = pd.read_csv(args.dataset, usecols=["url", "label"]).dropna()
    frame["url"] = frame["url"].astype(str).str.strip()
    labels = frame["label"].astype(str).str.strip().str.lower().map({
        "0": 0, "benign": 0, "legitimate": 0, "1": 1, "phishing": 1, "malicious": 1,
    })
    frame["label"] = labels
    frame = frame.dropna(subset=["label"]).drop_duplicates(subset=["url"])
    truth = frame["label"].astype(int)
    if truth.nunique() != 2:
        raise ValueError("Evaluation data must contain both classes.")
    model = joblib.load(args.model)
    prediction = model.predict(frame["url"])
    matrix = confusion_matrix(truth, prediction, labels=[0, 1])
    precision, recall, f1, _ = precision_recall_fscore_support(
        truth, prediction, average="binary", zero_division=0
    )
    result = {
        "rows": int(len(frame)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": float(roc_auc_score(truth, model.predict_proba(frame["url"])[:, 1])),
        "false_positive_rate": float(matrix[0, 1] / max(1, matrix[0].sum())),
        "false_negative_rate": float(matrix[1, 0] / max(1, matrix[1].sum())),
        "confusion_matrix_labels_0_1": matrix.tolist(),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
