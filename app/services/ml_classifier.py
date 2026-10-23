import os
from pathlib import Path

MODEL_PATH = Path(os.environ.get("PHISHGUARD_MODEL_PATH", "instance/url_model.joblib"))


def model_status():
    return "Available" if MODEL_PATH.is_file() else "Not trained"


def classify_url(value):
    """Load an optional locally trained artifact; expose no probability claim."""
    if not MODEL_PATH.is_file():
        return {"available": False, "status": "Model not trained"}
    try:
        import joblib

        model = joblib.load(MODEL_PATH)
        label = int(model.predict([value])[0])
    except (OSError, ValueError, ImportError) as exc:
        return {"available": False, "status": f"Model unavailable ({type(exc).__name__})"}
    return {
        "available": True,
        "label": "phishing-like" if label == 1 else "benign-like",
        "status": "Uncalibrated model prediction; not a verified verdict",
    }
