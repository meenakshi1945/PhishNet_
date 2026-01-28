import math, base64, re
from bs4 import BeautifulSoup
from typing import Dict

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    probs = [float(data.count(c)) / len(data) for c in set(data)]
    entropy = -sum(p * math.log2(p) for p in probs)
    return entropy

def detect_obfuscation(js: str) -> list:
    patterns = {
        
        "base64_decode": r"(atob\s*\(|btoa\s*\()",

        
        "base64_blob": r"[A-Za-z0-9+/]{20,}={0,2}",

        
        "eval_usage": r"eval\s*\(",

        
        "hex_escape": r"(\\x[0-9A-Fa-f]{2})",

        
        "function_constructor": r"new Function\s*\(",
    }

    hits = []
    for name, pat in patterns.items():
        if re.search(pat, js or "", re.IGNORECASE):
            hits.append(name)

    return hits


def count_iframes(html: str) -> int:
    soup = BeautifulSoup(html or "", "html.parser")
    return len(soup.find_all("iframe"))

def analyze_heuristics(url: str="", html: str="", js: str="") -> Dict:
    reasons = []
    score = 0.0

    
    ent_html = shannon_entropy(html or "")
    ent_js = shannon_entropy(js or "")
    if ent_js > 3.8:
        reasons.append(f"high_js_entropy:{ent_js:.2f}")
        score = max(score, 0.6)

    
    obf = detect_obfuscation(js)
    if obf:
        reasons.append(f"obfuscation:{','.join(obf)}")
        score = max(score, 0.7)

    
    if count_iframes(html) > 2:
        reasons.append("multiple_iframes")
        score = max(score, 0.55)

    
    if "meta refresh" in (html or "").lower() or "location.href" in (js or ""):
        reasons.append("redirect_behavior")
        score = max(score, 0.6)

    return {"suspicion_score": score, "reasons": reasons, "ent_html": ent_html, "ent_js": ent_js}
