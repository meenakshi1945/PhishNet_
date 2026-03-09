import argparse
import os
from typing import List

import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUTPUT = os.path.join(BASE_DIR, "urls.csv")


def _normalize_url(url: str) -> str:
    value = str(url or "").strip()
    if not value:
        return ""
    if "://" not in value:
        return f"http://{value}"
    return value


def _normalize_label(value) -> int:
    text = str(value).strip().lower()
    if text in {"1", "phishing", "malicious", "bad", "true"}:
        return 1
    if text in {"0", "legitimate", "benign", "safe", "false"}:
        return 0
    raise ValueError(f"Unsupported label value: {value}")


def _read_source(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    lowered = {col.lower(): col for col in df.columns}

    if "url" not in lowered:
        raise ValueError(f"{path}: missing 'url' column")

    label_col = None
    for candidate in ("label", "class", "target", "status"):
        if candidate in lowered:
            label_col = lowered[candidate]
            break
    if label_col is None:
        raise ValueError(f"{path}: missing label column (label/class/target/status)")

    out = pd.DataFrame()
    out["url"] = df[lowered["url"]].map(_normalize_url)
    out["label"] = df[label_col].map(_normalize_label)
    out = out[out["url"] != ""].copy()
    return out


def build_dataset(sources: List[str], output_path: str, max_per_class: int = 0) -> None:
    frames = [_read_source(src) for src in sources]
    merged = pd.concat(frames, ignore_index=True)
    merged = merged.drop_duplicates(subset=["url"], keep="first")

    if max_per_class > 0:
        sampled = []
        for label in (0, 1):
            part = merged[merged["label"] == label]
            sampled.append(part.sample(min(max_per_class, len(part)), random_state=42))
        merged = pd.concat(sampled, ignore_index=True)

    merged = merged.sample(frac=1.0, random_state=42).reset_index(drop=True)
    merged.to_csv(output_path, index=False)

    legit = int((merged["label"] == 0).sum())
    phish = int((merged["label"] == 1).sum())
    print(f"Saved merged dataset: {output_path}")
    print(f"Rows: {len(merged)} (legitimate={legit}, phishing={phish})")


def main():
    parser = argparse.ArgumentParser(
        description="Merge and normalize URL datasets into ml_lightweight/urls.csv"
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        required=True,
        help="CSV paths containing URL and label columns",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Output CSV path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--max-per-class",
        type=int,
        default=0,
        help="Optional max rows per class (0 means no cap)",
    )
    args = parser.parse_args()

    build_dataset(args.sources, args.output, args.max_per_class)


if __name__ == "__main__":
    main()
