
import re
def safe_text(x):
    return re.sub(r"\s+", " ", (x or "")).strip()
