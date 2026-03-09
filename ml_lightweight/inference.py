import os
import re
from ipaddress import ip_address
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import joblib
import pandas as pd

from features import FEATURE_COLUMNS, analyze_url_words, extract_features_from_url

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishnet_light_model.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "feature_columns.pkl")
EXPLAIN_META_PATH = os.path.join(BASE_DIR, "explainability_meta.pkl")
ANOMALY_MODEL_PATH = os.path.join(BASE_DIR, "phishnet_zero_day_model.pkl")
ANOMALY_PCA_MODEL_PATH = os.path.join(BASE_DIR, "phishnet_zero_day_pca_model.pkl")
ANOMALY_META_PATH = os.path.join(BASE_DIR, "zero_day_meta.pkl")


def _safe_load(path: str, default):
    try:
        return joblib.load(path)
    except Exception:
        return default


model = _safe_load(MODEL_PATH, None)
feature_columns = _safe_load(FEATURES_PATH, FEATURE_COLUMNS)
explainability_meta = _safe_load(EXPLAIN_META_PATH, {})
anomaly_model = _safe_load(ANOMALY_MODEL_PATH, None)
anomaly_pca_model = _safe_load(ANOMALY_PCA_MODEL_PATH, None)
anomaly_meta = _safe_load(ANOMALY_META_PATH, {})

COMMON_MULTI_PART_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "co.in",
    "com.au",
    "com.br",
    "co.jp",
    "co.kr",
    "co.nz",
    "com.sg",
    "com.mx",
}

HIGH_RISK_TLDS = {
    "zip",
    "mov",
    "click",
    "top",
    "xyz",
    "country",
    "gq",
    "tk",
    "work",
    "support",
    "cam",
    "rest",
    "fit",
}

# Lightweight curated set for brand impersonation checks.
BRAND_REFERENCE_DOMAINS = {
    "google": {"google.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "aws.amazon.com"},
    "paypal": {"paypal.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "linkedin": {"linkedin.com"},
    "github": {"github.com"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "telegram": {"telegram.org"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "bankofamerica": {"bankofamerica.com"},
}

LEET_MAP = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "2": "z",
        "3": "e",
        "4": "a",
        "5": "s",
        "6": "g",
        "7": "t",
        "8": "b",
        "9": "g",
        "$": "s",
        "@": "a",
    }
)


def _normalize_url(url: str) -> str:
    value = (url or "").strip()
    if not value:
        return ""
    if "://" not in value:
        return f"http://{value}"
    return value


def _is_ip(host: str) -> bool:
    if not host:
        return False
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def _registered_domain(host: str) -> str:
    if not host or _is_ip(host):
        return host
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    tail2 = ".".join(labels[-2:])
    tail3 = ".".join(labels[-3:])
    if tail2 in COMMON_MULTI_PART_SUFFIXES:
        return tail3
    return tail2


def _domain_parts(host: str) -> Tuple[str, str]:
    reg = _registered_domain(host)
    labels = reg.split(".") if reg else []
    if len(labels) < 2:
        return reg, ""
    return labels[0], labels[-1]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        curr = [i]
        for j, ch_b in enumerate(b, start=1):
            insert_cost = curr[j - 1] + 1
            delete_cost = prev[j] + 1
            replace_cost = prev[j - 1] + (0 if ch_a == ch_b else 1)
            curr.append(min(insert_cost, delete_cost, replace_cost))
        prev = curr
    return prev[-1]


def _lookalike_brand_signals(host: str, full_url: str) -> List[Tuple[float, str, str]]:
    if not host or _is_ip(host):
        return []

    sld, _ = _domain_parts(host)
    compact_sld = re.sub(r"[^a-z0-9]", "", sld)
    translated_sld = compact_sld.translate(LEET_MAP)
    lower_host = host.lower()
    lower_url = (full_url or "").lower()
    signals: List[Tuple[float, str, str]] = []

    for brand, official_domains in BRAND_REFERENCE_DOMAINS.items():
        # Brand token appears in host/path but domain is not the official one.
        if brand in lower_url and not any(
            lower_host == dom or lower_host.endswith(f".{dom}") for dom in official_domains
        ):
            signals.append(
                (
                    0.23,
                    f"brand_impersonation:{brand}",
                    f"This URL references '{brand}' but the domain is not an official {brand} domain.",
                )
            )

        # Detect small typos and leetspeak substitutions (e.g. go0gle).
        if len(translated_sld) >= max(4, len(brand) - 1):
            distance = _levenshtein(translated_sld, brand)
            if brand in translated_sld and brand not in compact_sld:
                signals.append(
                    (
                        0.4,
                        f"typosquat:{brand}",
                        f"The domain appears to hide '{brand}' via lookalike character substitutions.",
                    )
                )
            elif compact_sld != brand and translated_sld == brand:
                signals.append(
                    (
                        0.55,
                        f"typosquat:{brand}",
                        f"The domain uses lookalike character substitutions to mimic '{brand}' (example: 0/o, 1/l).",
                    )
                )
            elif translated_sld != brand and distance <= 1:
                signals.append(
                    (
                        0.45,
                        f"typosquat:{brand}",
                        f"The domain name is a close lookalike of '{brand}' (possible typosquatting).",
                    )
                )
            elif len(brand) >= 8 and translated_sld != brand and distance == 2:
                signals.append(
                    (
                        0.28,
                        f"typosquat:{brand}",
                        f"The domain appears visually similar to '{brand}' with minor character changes.",
                    )
                )

    return signals


def _deep_url_risk_analysis(url: str, features: dict) -> Dict[str, object]:
    normalized = _normalize_url(url)
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower().strip(".")
    sld, tld = _domain_parts(host)
    risk_score = 0.0
    signals: List[Tuple[float, str, str]] = []

    if "@" in normalized:
        signals.append(
            (
                0.22,
                "at_symbol_obfuscation",
                "This URL contains '@', which can hide the true destination.",
            )
        )
    if "xn--" in host:
        signals.append(
            (
                0.26,
                "punycode_domain",
                "The domain uses punycode ('xn--'), a common pattern in homograph attacks.",
            )
        )
    if any(ord(ch) > 127 for ch in host):
        signals.append(
            (
                0.18,
                "non_ascii_host",
                "The hostname includes non-ASCII characters, which can be used for visual impersonation.",
            )
        )
    if tld in HIGH_RISK_TLDS:
        signals.append(
            (
                0.14,
                f"high_risk_tld:{tld}",
                f"The domain uses '.{tld}', a TLD often abused in phishing campaigns.",
            )
        )
    if host.count("-") >= 2:
        signals.append(
            (
                0.1,
                "hyphen_heavy_host",
                "The domain contains many hyphens, a common phishing obfuscation pattern.",
            )
        )
    if features.get("num_subdomains", 0) >= 3:
        signals.append(
            (
                0.15,
                "excessive_subdomains",
                "The URL has many subdomain layers, often used to disguise the real domain.",
            )
        )
    if features.get("has_ip_address", 0) == 1:
        signals.append(
            (
                0.3,
                "ip_literal_host",
                "The URL uses an IP address directly instead of a normal domain name.",
            )
        )
    if features.get("uses_https", 1) == 0:
        signals.append(
            (
                0.12,
                "no_https",
                "The URL does not use HTTPS encryption.",
            )
        )
    if features.get("url_entropy", 0.0) >= 4.2:
        signals.append(
            (
                0.14,
                "high_entropy_url",
                "The URL text looks unusually random, which can indicate generated phishing links.",
            )
        )
    if features.get("encoded_char_count", 0) >= 2:
        signals.append(
            (
                0.16,
                "heavy_url_encoding",
                "The URL has multiple encoded character sequences used to hide intent.",
            )
        )
    if features.get("redirect_marker_count", 0) >= 1:
        signals.append(
            (
                0.14,
                "redirect_parameter",
                "The URL includes redirect parameters that may forward to a different destination.",
            )
        )
    if features.get("has_redirection_pattern", 0) == 1:
        signals.append(
            (
                0.12,
                "redirect_path_pattern",
                "The URL structure indicates redirect-like behavior.",
            )
        )
    if features.get("num_special_chars", 0) >= 8:
        signals.append(
            (
                0.11,
                "symbol_heavy_url",
                "The URL uses many separators/symbols, a common obfuscation technique.",
            )
        )
    if features.get("num_digits", 0) >= 8:
        signals.append(
            (
                0.11,
                "digit_heavy_url",
                "The URL contains an unusually high number of digits.",
            )
        )
    if (
        features.get("unique_token_ratio", 1.0) >= 0.95
        and features.get("token_count", 0) >= 6
        and features.get("longest_token_length", 0) >= 12
    ):
        signals.append(
            (
                0.1,
                "synthetic_token_pattern",
                "The URL tokens appear synthetic/random, which is common in newly generated phishing links.",
            )
        )
    if sld and len(sld) >= 20:
        signals.append(
            (
                0.08,
                "very_long_sld",
                "The main domain token is unusually long and may be algorithmically generated.",
            )
        )

    signals.extend(_lookalike_brand_signals(host, normalized))
    risk_score = min(1.0, sum(weight for weight, _, _ in signals))

    sorted_signals = sorted(signals, key=lambda item: item[0], reverse=True)
    reasons = [reason for _, _, reason in sorted_signals]
    tags = [tag for _, tag, _ in sorted_signals]
    critical = any(tag.startswith("typosquat:") for tag in tags) or any(
        tag == "punycode_domain" for tag in tags
    )

    return {
        "score": round(risk_score, 4),
        "reasons": reasons[:5],
        "tags": tags,
        "critical": critical,
    }


def _risk_level(score: float) -> str:
    if score >= 0.85:
        return "critical"
    if score >= 0.65:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def _recommended_action(level: str) -> str:
    if level == "critical":
        return "block_and_investigate"
    if level == "high":
        return "warn_and_require_manual_verification"
    if level == "medium":
        return "show_caution_and_limit_sensitive_actions"
    return "allow_with_monitoring"


def _zero_day_anomaly_analysis(X: pd.DataFrame, tokens: List[str]) -> Dict[str, object]:
    if anomaly_model is None and anomaly_pca_model is None:
        return {
            "available": False,
            "flag": False,
            "decision_score": None,
            "threshold": None,
            "score": 0.0,
        }

    weights = anomaly_meta.get("weights", {"iforest": 0.5, "pca": 0.3, "token_novelty": 0.2})
    iforest_threshold = float(anomaly_meta.get("iforest_threshold", -0.02))
    pca_error_threshold = float(anomaly_meta.get("pca_error_threshold", 0.1))
    combined_threshold = float(anomaly_meta.get("combined_score_threshold", 0.45))
    benign_vocab = set(anomaly_meta.get("benign_token_vocab", []))

    iforest_score = 0.0
    iforest_flag = False
    iforest_decision = None
    pca_score = 0.0
    pca_flag = False
    pca_error = None

    try:
        if anomaly_model is not None:
            iforest_decision = float(anomaly_model.decision_function(X)[0])
            margin = iforest_threshold - iforest_decision
            iforest_score = 0.0 if margin <= 0 else min(1.0, margin / (abs(iforest_threshold) + 0.15))
            iforest_flag = iforest_decision < iforest_threshold

        if anomaly_pca_model is not None:
            scaled = anomaly_pca_model.named_steps["scaler"].transform(X)
            pca = anomaly_pca_model.named_steps["pca"]
            compressed = pca.transform(scaled)
            restored = pca.inverse_transform(compressed)
            pca_error = float(((scaled - restored) ** 2).mean())
            pca_margin = pca_error - pca_error_threshold
            pca_score = 0.0 if pca_margin <= 0 else min(1.0, pca_margin / (pca_error_threshold + 0.15))
            pca_flag = pca_error > pca_error_threshold
    except Exception:
        return {
            "available": False,
            "flag": False,
            "decision_score": None,
            "threshold": combined_threshold,
            "score": 0.0,
        }

    filtered_tokens = [tok for tok in tokens if len(tok) >= 3 and not tok.isdigit()]
    if filtered_tokens and benign_vocab:
        unseen = [tok for tok in filtered_tokens if tok not in benign_vocab]
        token_novelty_ratio = len(unseen) / len(filtered_tokens)
    else:
        token_novelty_ratio = 0.0
    token_novelty_score = min(1.0, token_novelty_ratio / 0.75)

    combined_score = (
        float(weights.get("iforest", 0.5)) * iforest_score
        + float(weights.get("pca", 0.3)) * pca_score
        + float(weights.get("token_novelty", 0.2)) * token_novelty_score
    )
    hard_flag = iforest_flag and pca_flag
    flag = hard_flag or combined_score >= combined_threshold

    return {
        "available": True,
        "flag": bool(flag),
        "decision_score": round(combined_score, 4),
        "threshold": round(combined_threshold, 4),
        "score": round(combined_score, 4),
        "iforest_decision": None if iforest_decision is None else round(iforest_decision, 4),
        "pca_error": None if pca_error is None else round(pca_error, 4),
        "token_novelty_ratio": round(token_novelty_ratio, 4),
    }


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
    deep_analysis = _deep_url_risk_analysis(url, features)
    tokens = word_analysis.get("tokens", [])
    suspicious_tokens = word_analysis.get("suspicious_tokens", [])
    zero_day = _zero_day_anomaly_analysis(X, tokens)

    token_preview = ", ".join(tokens[:12]) if tokens else "none"
    if len(tokens) > 12:
        token_preview = f"{token_preview}, and {len(tokens) - 12} more"

    if model is None:
        fallback_reasons = _rank_reasons(_rule_based_reasons(features))
        fallback_reasons = deep_analysis["reasons"] + fallback_reasons
        if not fallback_reasons:
            fallback_reasons = ["Model artifact unavailable; returned heuristic estimate"]
        fallback_reasons.insert(0, f"Words seen in this link: {token_preview}.")
        if suspicious_tokens:
            fallback_reasons.insert(
                1,
                "Suspicious words detected: " + ", ".join(suspicious_tokens) + ".",
            )
        model_estimate = 0.5
        combined_confidence = max(model_estimate, float(deep_analysis.get("score", 0.0)))
        combined_confidence = max(combined_confidence, float(zero_day.get("score", 0.0)))
        if deep_analysis.get("critical"):
            combined_confidence = max(combined_confidence, 0.9)
        if zero_day.get("flag"):
            combined_confidence = max(combined_confidence, 0.7)
            fallback_reasons.insert(
                2,
                "This URL is structurally anomalous compared with known legitimate URLs (zero-day indicator).",
            )
        is_phishing = combined_confidence >= 0.5 or bool(deep_analysis.get("critical"))
        risk_level = _risk_level(combined_confidence)
        return {
            "label": "phishing" if is_phishing else "legitimate",
            "confidence": round(combined_confidence, 4),
            "risk_level": risk_level,
            "recommended_action": _recommended_action(risk_level),
            "analysis_tags": deep_analysis.get("tags", []),
            "zero_day_flag": bool(zero_day.get("flag", False)),
            "zero_day_score": float(zero_day.get("score", 0.0)),
            "anomaly_decision_score": zero_day.get("decision_score"),
            "anomaly_threshold": zero_day.get("threshold"),
            "reasons": fallback_reasons[:6],
        }

    probabilities = model.predict_proba(X)[0]
    model_confidence = float(probabilities[1])
    deep_score = float(deep_analysis.get("score", 0.0))
    zero_day_score = float(zero_day.get("score", 0.0))
    combined_confidence = max(model_confidence, deep_score, zero_day_score)
    if deep_analysis.get("critical"):
        combined_confidence = max(combined_confidence, 0.9)
    if zero_day.get("flag"):
        combined_confidence = max(combined_confidence, 0.7)
    label = "phishing" if (combined_confidence >= 0.5 or deep_analysis.get("critical")) else "legitimate"

    reasons = _rank_reasons(_rule_based_reasons(features))
    reasons = deep_analysis["reasons"] + reasons
    reasons.insert(0, f"Words seen in this link: {token_preview}.")
    if suspicious_tokens:
        reasons.insert(1, "Suspicious words detected: " + ", ".join(suspicious_tokens) + ".")
    if zero_day.get("flag"):
        reasons.insert(
            2,
            "This URL is structurally anomalous compared with known legitimate URLs (zero-day indicator).",
        )
    if not reasons:
        reasons = ["No strong phishing indicators were triggered."]
    elif combined_confidence < 0.5:
        reasons = reasons[:4]

    risk_level = _risk_level(combined_confidence)
    return {
        "label": label,
        "confidence": round(combined_confidence, 4),
        "model_confidence": round(model_confidence, 4),
        "deep_risk_score": round(deep_score, 4),
        "zero_day_score": zero_day_score,
        "zero_day_flag": bool(zero_day.get("flag", False)),
        "anomaly_decision_score": zero_day.get("decision_score"),
        "anomaly_threshold": zero_day.get("threshold"),
        "risk_level": risk_level,
        "recommended_action": _recommended_action(risk_level),
        "analysis_tags": deep_analysis.get("tags", []),
        "reasons": reasons[:6],
    }


if __name__ == "__main__":
    test_url = "http://secure-login-update-paypal.com/verify?redirect=http://example.com"
    print(predict_url(test_url))
