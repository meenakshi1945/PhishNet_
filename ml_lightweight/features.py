import math
import re
from ipaddress import ip_address
from urllib.parse import urlparse, unquote

SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "signin",
    "password",
    "bank",
    "wallet",
    "payment",
    "confirm",
    "alert",
}

FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "path_length",
    "num_subdomains",
    "num_dots",
    "num_digits",
    "num_special_chars",
    "has_ip_address",
    "suspicious_keyword_count",
    "url_entropy",
    "uses_https",
    "encoded_char_count",
    "redirect_marker_count",
    "has_redirection_pattern",
    "domain_age_days",
    "token_count",
    "suspicious_token_ratio",
    "longest_token_length",
    "unique_token_ratio",
]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequency = {}
    for char in value:
        frequency[char] = frequency.get(char, 0) + 1
    entropy = 0.0
    value_len = len(value)
    for count in frequency.values():
        prob = count / value_len
        entropy -= prob * math.log2(prob)
    return entropy


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        return f"http://{url}"
    return url


def _extract_host(parsed) -> str:
    host = parsed.hostname or ""
    return host.lower()


def _is_ip(host: str) -> int:
    if not host:
        return 0
    try:
        ip_address(host)
        return 1
    except ValueError:
        return 0


def _subdomain_count(host: str) -> int:
    if not host:
        return 0
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


def _suspicious_keyword_count(url: str) -> int:
    lower_url = url.lower()
    return sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in lower_url)


def _tokenize_url_words(url: str):
    # Break the URL into readable word-like chunks across host, path, and query.
    return [token for token in re.split(r"[^a-zA-Z0-9]+", url.lower()) if token]


def analyze_url_words(url: str) -> dict:
    tokens = _tokenize_url_words(url)
    suspicious_tokens = [tok for tok in tokens if tok in SUSPICIOUS_KEYWORDS]
    unique_count = len(set(tokens))
    token_count = len(tokens)

    return {
        "tokens": tokens,
        "suspicious_tokens": sorted(set(suspicious_tokens)),
        "token_count": token_count,
        "suspicious_token_ratio": (len(suspicious_tokens) / token_count) if token_count else 0.0,
        "longest_token_length": max((len(tok) for tok in tokens), default=0),
        "unique_token_ratio": (unique_count / token_count) if token_count else 0.0,
    }


def _special_character_count(url: str) -> int:
    return sum(1 for char in url if not char.isalnum())


def _encoded_character_count(url: str) -> int:
    return len(re.findall(r"%[0-9a-fA-F]{2}", url))


def _redirect_marker_count(url: str) -> int:
    lower = url.lower()
    markers = ["redirect=", "url=", "next=", "continue=", "return=", "dest="]
    return sum(lower.count(marker) for marker in markers)


def extract_features_from_url(url: str, domain_age_days: int = 0):
    normalized = _normalize_url(url)
    parsed = urlparse(normalized)
    host = _extract_host(parsed)
    path_query = f"{parsed.path or ''}{parsed.query or ''}"

    raw_double_slash_count = max(0, normalized.count("//") - 1)
    path_has_double_slash = int("//" in (parsed.path or ""))
    has_redirection_pattern = int(raw_double_slash_count > 0 or path_has_double_slash > 0)

    decoded = unquote(normalized)
    entropy_source = decoded if decoded else normalized
    word_analysis = analyze_url_words(normalized)

    features = {
        "url_length": len(normalized),
        "domain_length": len(host),
        "path_length": len(parsed.path or ""),
        "num_subdomains": _subdomain_count(host),
        "num_dots": host.count("."),
        "num_digits": sum(char.isdigit() for char in normalized),
        "num_special_chars": _special_character_count(normalized),
        "has_ip_address": _is_ip(host),
        "suspicious_keyword_count": _suspicious_keyword_count(normalized),
        "url_entropy": shannon_entropy(entropy_source),
        "uses_https": int(parsed.scheme.lower() == "https"),
        "encoded_char_count": _encoded_character_count(normalized),
        "redirect_marker_count": _redirect_marker_count(path_query),
        "has_redirection_pattern": has_redirection_pattern,
        # Placeholder until WHOIS/domain-age enrichment is integrated.
        "domain_age_days": int(max(0, domain_age_days)),
        "token_count": word_analysis["token_count"],
        "suspicious_token_ratio": word_analysis["suspicious_token_ratio"],
        "longest_token_length": word_analysis["longest_token_length"],
        "unique_token_ratio": word_analysis["unique_token_ratio"],
    }

    return features


def to_feature_vector(features: dict):
    return [float(features.get(col, 0.0)) for col in FEATURE_COLUMNS]
