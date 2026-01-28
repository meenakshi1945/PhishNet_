from fastapi import APIRouter, Body
from pydantic import BaseModel
from typing import Optional, Dict, Any
from app.core.heuristics import analyze_heuristics
from app.core.signatures import run_yara, run_clam_like
from app.core.ml_infer import infer_model
from app.core.ml_infer import lightweight_ml_scan

router = APIRouter()

class ScanRequest(BaseModel):
    url: Optional[str] = None
    html: Optional[str] = None
    js: Optional[str] = None

@router.post("/page")
async def scan_page(payload: ScanRequest):
    
    html = payload.html or ""
    js = payload.js or ""
    url = payload.url or ""

    
    heuristics_report = analyze_heuristics(url=url, html=html, js=js)

   
    yara_matches = run_yara(html + js)
    clam_matches = run_clam_like(html + js)

    
    ml_score, ml_explain = infer_model(url=url, html=html)

    
    score = max(ml_score, heuristics_report.get("suspicion_score", 0))
    reasons = {
        "heuristics": heuristics_report.get("reasons"),
        "yara": yara_matches,
        "clam": clam_matches,
        "ml": ml_explain
    }

    result = {
        "url": url,
        "final_score": float(score),
        "reasons": reasons
    }
    return result
@router.post("/scan-light")
def scan_light(payload: dict):
    url = payload.get("url")
    if not url:
        return {"error": "URL is required"}

    result = lightweight_ml_scan(url)

    return {
        "engine": "lightweight-ml",
        "result": result
    }
