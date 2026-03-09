import os
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

import requests

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
DENYLIST_PATH = RULES_DIR / "domain_denylist.txt"

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


def _normalize_url(url: str) -> str:
    value = (url or "").strip()
    if not value:
        return ""
    if "://" not in value:
        return f"http://{value}"
    return value


def _extract_host(url: str) -> str:
    try:
        parsed = urlparse(_normalize_url(url))
        return (parsed.hostname or "").lower().strip(".")
    except Exception:
        return ""


def _registered_domain(host: str) -> str:
    labels = [label for label in (host or "").split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    tail2 = ".".join(labels[-2:])
    tail3 = ".".join(labels[-3:])
    if tail2 in COMMON_MULTI_PART_SUFFIXES:
        return tail3
    return tail2


def _load_local_denylist() -> set:
    if not DENYLIST_PATH.exists():
        return set()
    domains = set()
    for line in DENYLIST_PATH.read_text(encoding="utf-8").splitlines():
        value = line.strip().lower()
        if not value or value.startswith("#"):
            continue
        domains.add(value)
    return domains


def _local_denylist_lookup(url: str, denylist: set) -> Dict[str, object]:
    host = _extract_host(url)
    reg_domain = _registered_domain(host)
    if not host:
        return {"matched": False}

    candidates = {host, reg_domain}
    if any(domain in denylist for domain in candidates if domain):
        return {
            "matched": True,
            "source": "local_denylist",
            "reason": "Domain appears in local threat-intel denylist.",
            "confidence": 0.98,
        }
    return {"matched": False}


def _google_safe_browsing_lookup(url: str) -> Dict[str, object]:
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return {"matched": False, "skipped": "missing_api_key"}

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={api_key}"
    )
    body = {
        "client": {"clientId": "phishnet", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": _normalize_url(url)}],
        },
    }
    try:
        response = requests.post(endpoint, json=body, timeout=3)
        if response.status_code != 200:
            return {"matched": False, "error": f"http_{response.status_code}"}
        payload = response.json()
        matches = payload.get("matches", [])
        if matches:
            types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
            return {
                "matched": True,
                "source": "google_safe_browsing",
                "reason": "URL matched Google Safe Browsing threat list.",
                "confidence": 0.99,
                "details": {"threat_types": types},
            }
        return {"matched": False}
    except Exception as exc:
        return {"matched": False, "error": str(exc)}


def lookup_threat_intel(url: str) -> Dict[str, object]:
    denylist = _load_local_denylist()
    signals: List[Dict[str, object]] = []

    local_signal = _local_denylist_lookup(url, denylist)
    if local_signal.get("matched"):
        signals.append(local_signal)

    gsb_signal = _google_safe_browsing_lookup(url)
    if gsb_signal.get("matched"):
        signals.append(gsb_signal)

    if not signals:
        return {
            "matched": False,
            "sources": [],
            "confidence": 0.0,
            "reasons": [],
        }

    confidence = max(float(sig.get("confidence", 0.0)) for sig in signals)
    sources = [str(sig.get("source", "unknown")) for sig in signals]
    reasons = [str(sig.get("reason", "Threat-intel match")) for sig in signals]
    details = [sig.get("details") for sig in signals if sig.get("details")]
    return {
        "matched": True,
        "sources": sources,
        "confidence": round(confidence, 4),
        "reasons": reasons,
        "details": details,
    }
