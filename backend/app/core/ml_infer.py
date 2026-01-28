import onnxruntime as rt
import numpy as np
from typing import Tuple
import sys
import os

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
    return predict_url(url)

