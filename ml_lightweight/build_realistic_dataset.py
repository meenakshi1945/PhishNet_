import argparse
import os
from typing import List, Tuple
from urllib.parse import urlparse

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TRAIN = os.path.join(BASE_DIR, "urls_train.csv")
DEFAULT_HOLDOUT = os.path.join(BASE_DIR, "urls_holdout.csv")

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


def _registered_domain(url: str) -> str:
    host = (urlparse(_normalize_url(url)).hostname or "").lower().strip(".")
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    tail2 = ".".join(labels[-2:])
    tail3 = ".".join(labels[-3:])
    if tail2 in COMMON_MULTI_PART_SUFFIXES:
        return tail3
    return tail2


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


def _balance(df: pd.DataFrame, max_per_class: int) -> pd.DataFrame:
    if max_per_class <= 0:
        return df
    sampled = []
    for label in (0, 1):
        part = df[df["label"] == label]
        sampled.append(part.sample(min(max_per_class, len(part)), random_state=42))
    return pd.concat(sampled, ignore_index=True)


def _split_group_holdout(df: pd.DataFrame, holdout_size: float) -> Tuple[pd.DataFrame, pd.DataFrame]:
    groups = df["url"].map(_registered_domain)
    gss = GroupShuffleSplit(n_splits=1, test_size=holdout_size, random_state=42)
    train_idx, holdout_idx = next(gss.split(df[["url"]], df["label"], groups=groups))
    train_df = df.iloc[train_idx].copy()
    holdout_df = df.iloc[holdout_idx].copy()
    return train_df, holdout_df


def main():
    parser = argparse.ArgumentParser(
        description="Build realistic URL train/holdout datasets with strict domain-group split."
    )
    parser.add_argument("--sources", nargs="+", required=True, help="Input CSV paths")
    parser.add_argument("--train-output", default=DEFAULT_TRAIN, help="Train output CSV path")
    parser.add_argument("--holdout-output", default=DEFAULT_HOLDOUT, help="Holdout output CSV path")
    parser.add_argument("--holdout-size", type=float, default=0.2, help="Holdout fraction (0-1)")
    parser.add_argument("--max-per-class", type=int, default=0, help="Optional class cap (0 means no cap)")
    args = parser.parse_args()

    frames = [_read_source(path) for path in args.sources]
    merged = pd.concat(frames, ignore_index=True)
    merged = merged.drop_duplicates(subset=["url"], keep="first")
    merged = _balance(merged, args.max_per_class)
    merged = merged.sample(frac=1.0, random_state=42).reset_index(drop=True)

    train_df, holdout_df = _split_group_holdout(merged, args.holdout_size)
    train_df.to_csv(args.train_output, index=False)
    holdout_df.to_csv(args.holdout_output, index=False)

    print(f"Saved train set: {args.train_output} ({len(train_df)} rows)")
    print(f"Saved holdout set: {args.holdout_output} ({len(holdout_df)} rows)")
    print(
        f"Train class balance: legit={(train_df['label']==0).sum()}, phish={(train_df['label']==1).sum()}"
    )
    print(
        f"Holdout class balance: legit={(holdout_df['label']==0).sum()}, phish={(holdout_df['label']==1).sum()}"
    )


if __name__ == "__main__":
    main()
