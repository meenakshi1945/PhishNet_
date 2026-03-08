import os
from typing import List, Tuple

import joblib
import pandas as pd

from features import FEATURE_COLUMNS, analyze_url_words, extract_features_from_url

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishnet_light_model.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "feature_columns.pkl")
EXPLAIN_META_PATH = os.path.join(BASE_DIR, "explainability_meta.pkl")


def _safe_load(path: str, default):
    try:
        return joblib.load(path)
    except Exception:
        return default


model = _safe_load(MODEL_PATH, None)
feature_columns = _safe_load(FEATURES_PATH, FEATURE_COLUMNS)
explainability_meta = _safe_load(EXPLAIN_META_PATH, {})


def _build_feature_frame(url: str) -> Tuple[dict, pd.DataFrame]:
    feats = extract_features_from_url(url)
    ordered = {col: feats.get(col, 0.0) for col in feature_columns}
    return feats, pd.DataFrame([ordered], columns=feature_columns)


def _feature_importance_lookup() -> dict:
    feature_importance = explainability_meta.get("feature_importance", {})
    if feature_importance:
        return feature_importance

    if model is None:
        return {}

    try:
        estimator = model.named_steps["classifier"]
        return dict(zip(feature_columns, estimator.feature_importances_))
    except Exception:
        return {}


def _thresholds() -> dict:
    return explainability_meta.get("thresholds", {})


def _rule_based_reasons(features: dict) -> List[Tuple[str, str]]:
    thresholds = _thresholds()
    reasons: List[Tuple[str, str]] = []

    if features.get("suspicious_keyword_count", 0) > 0:
        reasons.append(
            (
                "suspicious_keyword_count",
                "This link uses urgency or account-related words that are common in scam messages.",
            )
        )
    if features.get("num_subdomains", 0) >= thresholds.get("num_subdomains", 1.0):
        reasons.append(
            (
                "num_subdomains",
                "The address has many sections before the main site name, which can be used to mimic trusted brands.",
            )
        )
    if features.get("url_entropy", 0.0) >= thresholds.get("url_entropy", 4.0):
        reasons.append(
            (
                "url_entropy",
                "The link text looks unusually random, a pattern often seen in phishing URLs.",
            )
        )
    if features.get("uses_https", 1) == 0:
        reasons.append(
            (
                "uses_https",
                "The link does not use secure HTTPS encryption.",
            )
        )
    if features.get("has_ip_address", 0) == 1:
        reasons.append(
            (
                "has_ip_address",
                "The link uses a raw IP address instead of a normal website name.",
            )
        )
    if features.get("encoded_char_count", 0) >= thresholds.get("encoded_char_count", 1.0):
        reasons.append(
            (
                "encoded_char_count",
                "Parts of the link are hidden using encoded characters.",
            )
        )
    if features.get("redirect_marker_count", 0) >= thresholds.get("redirect_marker_count", 1.0):
        reasons.append(
            (
                "redirect_marker_count",
                "The link includes redirect parameters, which can bounce you to a different page.",
            )
        )
    if features.get("has_redirection_pattern", 0) == 1:
        reasons.append(
            (
                "has_redirection_pattern",
                "The link structure suggests redirection behavior.",
            )
        )
    if features.get("num_special_chars", 0) >= thresholds.get("num_special_chars", 3.0):
        reasons.append(
            (
                "num_special_chars",
                "The link has many symbols and separators, which can be used to obfuscate intent.",
            )
        )
    if features.get("num_digits", 0) >= thresholds.get("num_digits", 3.0):
        reasons.append(
            (
                "num_digits",
                "The link contains many numbers, which is common in auto-generated phishing URLs.",
            )
        )
    if features.get("domain_length", 0) >= thresholds.get("domain_length", 20.0):
        reasons.append(
            (
                "domain_length",
                "The site name is unusually long, which may be trying to imitate a trusted brand.",
            )
        )
    if features.get("domain_age_days", 0) < thresholds.get("domain_age_days", 30.0):
        reasons.append(
            (
                "domain_age_days",
                "The domain appears very new or its age cannot be verified.",
            )
        )
    if features.get("suspicious_token_ratio", 0.0) >= thresholds.get("suspicious_token_ratio", 0.15):
        reasons.append(
            (
                "suspicious_token_ratio",
                "A high portion of words in this link are commonly used in phishing campaigns.",
            )
        )
    if features.get("longest_token_length", 0) >= thresholds.get("longest_token_length", 12.0):
        reasons.append(
            (
                "longest_token_length",
                "The link contains very long word chunks, which can indicate generated or deceptive URLs.",
            )
        )

    return reasons


def _rank_reasons(reasons: List[Tuple[str, str]]) -> List[str]:
    importance = _feature_importance_lookup()
    ranked = sorted(reasons, key=lambda pair: float(importance.get(pair[0], 0.0)), reverse=True)
    return [reason for _, reason in ranked[:5]]


def predict_url(url: str):
    features, X = _build_feature_frame(url)
    word_analysis = analyze_url_words(url)
    tokens = word_analysis.get("tokens", [])
    suspicious_tokens = word_analysis.get("suspicious_tokens", [])

    token_preview = ", ".join(tokens[:12]) if tokens else "none"
    if len(tokens) > 12:
        token_preview = f"{token_preview}, and {len(tokens) - 12} more"

    if model is None:
        fallback_reasons = _rank_reasons(_rule_based_reasons(features))
        if not fallback_reasons:
            fallback_reasons = ["Model artifact unavailable; returned heuristic estimate"]
        fallback_reasons.insert(0, f"Words seen in this link: {token_preview}.")
        if suspicious_tokens:
            fallback_reasons.insert(
                1,
                "Suspicious words detected: " + ", ".join(suspicious_tokens) + ".",
            )
        return {
            "label": "phishing" if features.get("suspicious_keyword_count", 0) > 0 else "legitimate",
            "confidence": 0.5,
            "reasons": fallback_reasons,
        }

    probabilities = model.predict_proba(X)[0]
    confidence = float(probabilities[1])
    label = "phishing" if confidence >= 0.5 else "legitimate"

    reasons = _rank_reasons(_rule_based_reasons(features))
    reasons.insert(0, f"Words seen in this link: {token_preview}.")
    if suspicious_tokens:
        reasons.insert(1, "Suspicious words detected: " + ", ".join(suspicious_tokens) + ".")
    if not reasons:
        reasons = ["No strong phishing indicators were triggered."]
    elif confidence < 0.5:
        reasons = reasons[:4]

    return {
        "label": label,
        "confidence": round(confidence, 4),
        "reasons": reasons,
    }


if __name__ == "__main__":
    test_url = "http://secure-login-update-paypal.com/verify?redirect=http://example.com"
    print(predict_url(test_url))
