import os
import argparse

import joblib
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from features import FEATURE_COLUMNS, analyze_url_words

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_FEATURES_CSV = os.path.join(BASE_DIR, "features.csv")
DEFAULT_URLS_CSV = os.path.join(BASE_DIR, "urls.csv")
MODEL_PATH = os.path.join(BASE_DIR, "phishnet_light_model.pkl")
FEATURE_COLUMNS_PATH = os.path.join(BASE_DIR, "feature_columns.pkl")
EXPLAIN_META_PATH = os.path.join(BASE_DIR, "explainability_meta.pkl")
ANOMALY_MODEL_PATH = os.path.join(BASE_DIR, "phishnet_zero_day_model.pkl")
ANOMALY_PCA_MODEL_PATH = os.path.join(BASE_DIR, "phishnet_zero_day_pca_model.pkl")
ANOMALY_META_PATH = os.path.join(BASE_DIR, "zero_day_meta.pkl")
LABEL_COL = "label"


def build_model() -> Pipeline:
    # Deliberately regularized baseline to avoid overconfident synthetic-data scores.
    return Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "classifier",
                DecisionTreeClassifier(
                    max_depth=1,
                    min_samples_leaf=20,
                    random_state=42,
                    class_weight="balanced",
                ),
            ),
        ]
    )


def build_anomaly_model() -> Pipeline:
    return Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "detector",
                IsolationForest(
                    n_estimators=300,
                    contamination=0.02,
                    random_state=42,
                ),
            ),
        ]
    )


def build_pca_anomaly_model(n_features: int) -> Pipeline:
    components = max(2, min(8, n_features - 1))
    return Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("pca", PCA(n_components=components, random_state=42)),
        ]
    )


def _reconstruction_error(pca_model: Pipeline, X: pd.DataFrame) -> np.ndarray:
    scaled = pca_model.named_steps["scaler"].transform(X)
    pca = pca_model.named_steps["pca"]
    compressed = pca.transform(scaled)
    restored = pca.inverse_transform(compressed)
    return np.mean((scaled - restored) ** 2, axis=1)


def _build_benign_token_vocab(url_df: pd.DataFrame, max_tokens: int = 1500) -> list:
    benign_urls = url_df[url_df["label"] == 0]["url"].astype(str).tolist()
    counts = {}
    for url in benign_urls:
        tokens = analyze_url_words(url).get("tokens", [])
        for tok in tokens:
            if len(tok) < 3 or tok.isdigit():
                continue
            counts[tok] = counts.get(tok, 0) + 1

    ordered = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return [token for token, _ in ordered[:max_tokens]]


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


def _evaluate_split(y_true, y_pred) -> dict:
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def main():
    parser = argparse.ArgumentParser(description="Train phishing model and zero-day anomaly models.")
    parser.add_argument("--features", default=DEFAULT_FEATURES_CSV, help="Training features CSV path")
    parser.add_argument("--urls-csv", default=DEFAULT_URLS_CSV, help="URL CSV for token-vocab extraction")
    parser.add_argument(
        "--holdout-features",
        default="",
        help="Optional strict holdout features CSV for unbiased evaluation",
    )
    args = parser.parse_args()

    df = pd.read_csv(args.features)

    if LABEL_COL not in df.columns:
        raise ValueError(f"Expected '{LABEL_COL}' column in {args.features}")

    missing_features = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_features:
        raise ValueError(f"Missing expected feature columns: {missing_features}")

    y = df[LABEL_COL].astype(int)
    X = df[FEATURE_COLUMNS].copy()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=14,
        stratify=y,
    )

    model = build_model()
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    split_metrics = _evaluate_split(y_test, y_pred)

    print("\n=== Evaluation Metrics ===")
    print(f"Accuracy : {split_metrics['accuracy']:.4f}")
    print(f"Precision: {split_metrics['precision']:.4f}")
    print(f"Recall   : {split_metrics['recall']:.4f}")
    print(f"F1-score : {split_metrics['f1']:.4f}")
    print(
        f"Confusion: TN={split_metrics['tn']} FP={split_metrics['fp']} FN={split_metrics['fn']} TP={split_metrics['tp']}"
    )

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
            "accuracy": split_metrics["accuracy"],
            "precision": split_metrics["precision"],
            "recall": split_metrics["recall"],
            "f1": split_metrics["f1"],
            "tn": split_metrics["tn"],
            "fp": split_metrics["fp"],
            "fn": split_metrics["fn"],
            "tp": split_metrics["tp"],
        },
    }

    # Zero-day baseline: learn "normal legitimate URL" profile and flag outliers.
    anomaly_model = build_anomaly_model()
    X_legit_train = X_train[y_train == 0]
    if X_legit_train.empty:
        X_legit_train = X_train
    anomaly_model.fit(X_legit_train)
    pca_anomaly_model = build_pca_anomaly_model(X_train.shape[1])
    pca_anomaly_model.fit(X_legit_train)

    legit_test = X_test[y_test == 0]
    if legit_test.empty:
        legit_test = X_test
    legit_decisions = anomaly_model.decision_function(legit_test)
    iforest_threshold = float(pd.Series(legit_decisions).quantile(0.01))
    legit_reconstruction = _reconstruction_error(pca_anomaly_model, legit_test)
    pca_error_threshold = float(pd.Series(legit_reconstruction).quantile(0.99))

    phish_test = X_test[y_test == 1]
    if not phish_test.empty:
        phish_decisions = anomaly_model.decision_function(phish_test)
        phish_reconstruction = _reconstruction_error(pca_anomaly_model, phish_test)
        iforest_flags = phish_decisions < iforest_threshold
        pca_flags = phish_reconstruction > pca_error_threshold
        zero_day_recall = float((iforest_flags | pca_flags).mean())
    else:
        zero_day_recall = 0.0

    if os.path.exists(args.urls_csv):
        url_df = pd.read_csv(args.urls_csv)
        if "url" in url_df.columns and "label" in url_df.columns:
            url_df = url_df[["url", "label"]].copy()
            benign_token_vocab = _build_benign_token_vocab(url_df)
        else:
            benign_token_vocab = []
    else:
        benign_token_vocab = []

    zero_day_meta = {
        "iforest_threshold": iforest_threshold,
        "pca_error_threshold": pca_error_threshold,
        "combined_score_threshold": 0.45,
        "weights": {
            "iforest": 0.5,
            "pca": 0.3,
            "token_novelty": 0.2,
        },
        "contamination": 0.02,
        "legit_train_count": int(len(X_legit_train)),
        "legit_test_count": int(len(legit_test)),
        "phish_test_count": int(len(phish_test)),
        "zero_day_recall_proxy": zero_day_recall,
        "benign_token_vocab": benign_token_vocab,
    }

    if args.holdout_features:
        holdout_df = pd.read_csv(args.holdout_features)
        holdout_missing = [col for col in FEATURE_COLUMNS if col not in holdout_df.columns]
        if holdout_missing:
            raise ValueError(f"Holdout features missing expected columns: {holdout_missing}")
        holdout_X = holdout_df[FEATURE_COLUMNS].copy()
        holdout_y = holdout_df[LABEL_COL].astype(int)
        holdout_pred = model.predict(holdout_X)
        holdout_metrics = _evaluate_split(holdout_y, holdout_pred)
        explainability_meta["holdout_metrics"] = holdout_metrics
        print("\n=== Holdout Metrics ===")
        print(f"Accuracy : {holdout_metrics['accuracy']:.4f}")
        print(f"Precision: {holdout_metrics['precision']:.4f}")
        print(f"Recall   : {holdout_metrics['recall']:.4f}")
        print(f"F1-score : {holdout_metrics['f1']:.4f}")
        print(
            f"Confusion: TN={holdout_metrics['tn']} FP={holdout_metrics['fp']} FN={holdout_metrics['fn']} TP={holdout_metrics['tp']}"
        )

    joblib.dump(model, MODEL_PATH)
    joblib.dump(FEATURE_COLUMNS, FEATURE_COLUMNS_PATH)
    joblib.dump(explainability_meta, EXPLAIN_META_PATH)
    joblib.dump(anomaly_model, ANOMALY_MODEL_PATH)
    joblib.dump(pca_anomaly_model, ANOMALY_PCA_MODEL_PATH)
    joblib.dump(zero_day_meta, ANOMALY_META_PATH)

    print("\nModel artifacts saved:")
    print(f"- {MODEL_PATH}")
    print(f"- {FEATURE_COLUMNS_PATH}")
    print(f"- {EXPLAIN_META_PATH}")
    print(f"- {ANOMALY_MODEL_PATH}")
    print(f"- {ANOMALY_PCA_MODEL_PATH}")
    print(f"- {ANOMALY_META_PATH}")
    print(f"Zero-day IF threshold: {iforest_threshold:.4f}")
    print(f"Zero-day PCA threshold: {pca_error_threshold:.4f}")
    print(f"Zero-day recall proxy on phishing test split: {zero_day_recall:.4f}")


if __name__ == "__main__":
    main()
