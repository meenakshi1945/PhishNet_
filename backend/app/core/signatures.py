import yara
import json
import re
from pathlib import Path

RULES_PATH = Path(__file__).parent.parent / "rules"


yara_rules = None
try:
    yara_rules = yara.compile(str(RULES_PATH / "yara_rules.yar"))
except Exception as e:
    yara_rules = None

def run_yara(text: str):
    if not yara_rules:
        return []
    matches = yara_rules.match(data=text)
    return [m.rule for m in matches]


def run_clam_like(text: str):
    p = RULES_PATH / "clam_like_signatures.json"
    try:
        arr = json.loads(p.read_text())
    except Exception:
        return []
    hits = []
    for sig in arr:
        try:
            if re.search(sig["pattern"], text, re.IGNORECASE):
                hits.append(sig["name"])
        except re.error:
            continue
    return hits
