import math
from urllib.parse import urlparse

def shannon_entropy(s):
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0
    for c in freq:
        p = freq[c] / len(s)
        entropy -= p * math.log2(p)
    return entropy

def extract_features_from_url(url):
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "num_dots": hostname.count("."),
        "num_digits": sum(char.isdigit() for char in url),
        "has_at_symbol": int("@" in url),
        "has_hyphen": int("-" in hostname),
        "uses_https": int(parsed.scheme == "https"),
        "entropy": shannon_entropy(url),
        "path_length": len(path),
    }
