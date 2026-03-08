import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from features import FEATURE_COLUMNS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FEATURES_CSV = os.path.join(BASE_DIR, "features.csv")
MODEL_PATH = os.path.join(BASE_DIR, "phishnet_light_model.pkl")
FEATURE_COLUMNS_PATH = os.path.join(BASE_DIR, "feature_columns.pkl")
EXPLAIN_META_PATH = os.path.join(BASE_DIR, "explainability_meta.pkl")
LABEL_COL = "label"


def build_model() -> Pipeline:
    # Scaling keeps feature space stable for future model swaps.
    return Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=300,
                    max_depth=12,
                    min_samples_split=4,
                    min_samples_leaf=2,
                    random_state=42,
                    class_weight="balanced",
                ),
            ),
        ]
    )


def compute_thresholds(df: pd.DataFrame, label_col: str) -> dict:
    phishing = df[df[label_col] == 1]
    legitimate = df[df[label_col] == 0]

    def safe_quantile(series: pd.Series, value: float, fallback: float = 0.0) -> float:
        if series.empty:
            return fallback
        return float(series.quantile(value))

    return {
        "url_entropy": safe_quantile(phishing["url_entropy"], 0.7, 4.0),
        "num_subdomains": max(1.0, safe_quantile(phishing["num_subdomains"], 0.6, 1.0)),
        "num_special_chars": max(3.0, safe_quantile(phishing["num_special_chars"], 0.6, 3.0)),
        "num_digits": max(3.0, safe_quantile(phishing["num_digits"], 0.6, 3.0)),
        "suspicious_keyword_count": max(
            1.0, safe_quantile(phishing["suspicious_keyword_count"], 0.4, 1.0)
        ),
        "domain_length": max(20.0, safe_quantile(phishing["domain_length"], 0.6, 20.0)),
        "encoded_char_count": max(1.0, safe_quantile(phishing["encoded_char_count"], 0.6, 1.0)),
        "redirect_marker_count": max(
            1.0, safe_quantile(phishing["redirect_marker_count"], 0.6, 1.0)
        ),
        "domain_age_days": max(30.0, safe_quantile(legitimate["domain_age_days"], 0.2, 30.0)),
        "token_count": max(4.0, safe_quantile(phishing["token_count"], 0.6, 4.0)),
        "suspicious_token_ratio": max(
            0.15, safe_quantile(phishing["suspicious_token_ratio"], 0.6, 0.15)
        ),
        "longest_token_length": max(
            12.0, safe_quantile(phishing["longest_token_length"], 0.6, 12.0)
        ),
    }


def main():
    df = pd.read_csv(FEATURES_CSV)

    if LABEL_COL not in df.columns:
        raise ValueError(f"Expected '{LABEL_COL}' column in {FEATURES_CSV}")

    missing_features = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_features:
        raise ValueError(f"Missing expected feature columns: {missing_features}")

    y = df[LABEL_COL].astype(int)
    X = df[FEATURE_COLUMNS].copy()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    model = build_model()
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print("\n=== Evaluation Metrics ===")
    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1-score : {f1:.4f}")

    classifier = model.named_steps["classifier"]
    feature_importance = dict(
        sorted(
            zip(FEATURE_COLUMNS, classifier.feature_importances_),
            key=lambda pair: pair[1],
            reverse=True,
        )
    )

    explainability_meta = {
        "feature_importance": feature_importance,
        "thresholds": compute_thresholds(df, LABEL_COL),
        "metrics": {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
        },
    }

    joblib.dump(model, MODEL_PATH)
    joblib.dump(FEATURE_COLUMNS, FEATURE_COLUMNS_PATH)
    joblib.dump(explainability_meta, EXPLAIN_META_PATH)

    print("\nModel artifacts saved:")
    print(f"- {MODEL_PATH}")
    print(f"- {FEATURE_COLUMNS_PATH}")
    print(f"- {EXPLAIN_META_PATH}")


if __name__ == "__main__":
    main()
