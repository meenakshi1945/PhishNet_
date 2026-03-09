import onnxruntime as rt
import numpy as np
from typing import Tuple
import sys
import os
from app.core.threat_intel import lookup_threat_intel

ML_LIGHT_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml_lightweight")
)
if ML_LIGHT_PATH not in sys.path:
    sys.path.append(ML_LIGHT_PATH)

from inference import predict_url

MODEL_PATH = __file__.replace("ml_infer.py","../models/sample_model.onnx")

def extract_features(url: str, html: str) -> np.ndarray:
    url_len = len(url or "")
    html_len = len(html or "")
    ent = 0.0
    
    ent = (len(set(html)) / (html_len+1)) * 8
    return np.array([[url_len, html_len, ent]], dtype=np.float32)

def infer_model(url: str, html: str) -> Tuple[float, dict]:
    try:
        sess = rt.InferenceSession(MODEL_PATH)
        x = extract_features(url, html)
        name = sess.get_inputs()[0].name
        out = sess.run(None, {name: x})[0]
        score = float(out[0][0])
        explain = {"features": x.tolist()}
        return score, explain
    except Exception:
        
        return 0.45, {"fallback": True}
def lightweight_ml_scan(url: str):
    """
    Lightweight, explainable ML-based phishing detection.
    Returns label, confidence, and reasons.
    """
    result = predict_url(url)
    intel = lookup_threat_intel(url)
    result["threat_intel"] = intel

    if intel.get("matched"):
        result["label"] = "phishing"
        result["confidence"] = round(max(float(result.get("confidence", 0.0)), 0.97), 4)
        result["risk_level"] = "critical"
        result["recommended_action"] = "block_and_investigate"
        tags = list(result.get("analysis_tags", []))
        tags.append("threat_intel_match")
        result["analysis_tags"] = sorted(set(tags))
        reasons = list(result.get("reasons", []))
        reasons.insert(0, "Threat-intel feed flagged this URL as malicious.")
        for reason in intel.get("reasons", []):
            reasons.append(reason)
        result["reasons"] = reasons[:6]

    return result

