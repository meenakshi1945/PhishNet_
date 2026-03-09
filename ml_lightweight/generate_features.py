import os
import argparse

import pandas as pd

from features import FEATURE_COLUMNS, extract_features_from_url

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
URLS_CSV = os.path.join(BASE_DIR, "urls.csv")
FEATURES_CSV = os.path.join(BASE_DIR, "features.csv")


def main():
    parser = argparse.ArgumentParser(description="Generate numeric feature CSV from URL dataset.")
    parser.add_argument("--input", default=URLS_CSV, help="Input URLs CSV path")
    parser.add_argument("--output", default=FEATURES_CSV, help="Output features CSV path")
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError(f"{args.input} must include 'url' and 'label' columns")

    rows = []

    for _, row in df.iterrows():
        feats = extract_features_from_url(row["url"])
        ordered = {col: feats.get(col, 0.0) for col in FEATURE_COLUMNS}
        ordered["label"] = int(row["label"])
        rows.append(ordered)

    features_df = pd.DataFrame(rows)
    features_df.to_csv(args.output, index=False)
    print(f"Generated feature dataset: {args.output}")


if __name__ == "__main__":
    main()
