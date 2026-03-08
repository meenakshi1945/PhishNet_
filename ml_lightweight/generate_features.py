import os

import pandas as pd

from features import FEATURE_COLUMNS, extract_features_from_url

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
URLS_CSV = os.path.join(BASE_DIR, "urls.csv")
FEATURES_CSV = os.path.join(BASE_DIR, "features.csv")


def main():
    df = pd.read_csv(URLS_CSV)
    rows = []

    for _, row in df.iterrows():
        feats = extract_features_from_url(row["url"])
        ordered = {col: feats.get(col, 0.0) for col in FEATURE_COLUMNS}
        ordered["label"] = int(row["label"])
        rows.append(ordered)

    features_df = pd.DataFrame(rows)
    features_df.to_csv(FEATURES_CSV, index=False)
    print(f"Generated feature dataset: {FEATURES_CSV}")


if __name__ == "__main__":
    main()
