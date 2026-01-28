import pandas as pd
from features import extract_features_from_url

# Load raw URLs
df = pd.read_csv("urls.csv")

rows = []

for _, row in df.iterrows():
    feats = extract_features_from_url(row["url"])
    feats["label"] = row["label"]
    rows.append(feats)

# Create feature dataframe
features_df = pd.DataFrame(rows)

# Save features
features_df.to_csv("features.csv", index=False)

print("✅ features.csv generated successfully")
