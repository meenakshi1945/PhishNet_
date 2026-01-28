import joblib
import numpy as np
import pandas as pd
from features import extract_features_from_url
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(BASE_DIR, "phishnet_light_model.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "feature_columns.pkl")


model = joblib.load(MODEL_PATH)
feature_columns = joblib.load(FEATURES_PATH)

def predict_url(url):
    feats = extract_features_from_url(url)

    # Align features
    X = [feats.get(col, 0) for col in feature_columns]
    X = pd.DataFrame([feats], columns=feature_columns)

    prob = model.predict_proba(X)[0][1]
    label = int(prob >= 0.5)

    reasons = []
    if feats["entropy"] > 4:
        reasons.append("High URL entropy")
    if feats["num_digits"] > 5:
        reasons.append("Excessive digits in URL")
    if feats["has_at_symbol"]:
        reasons.append("Suspicious '@' symbol in URL")
    if not feats["uses_https"]:
        reasons.append("Non-HTTPS URL")

    return {
        "label": "phishing" if label else "benign",
        "confidence": round(prob, 3),
        "reasons": reasons
    }


# Quick test
if __name__ == "__main__":
    test_url = "http://secure-login-update-paypal.com"
    print(predict_url(test_url))
