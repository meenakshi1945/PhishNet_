import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

# Load generated features
df = pd.read_csv("features.csv")

# Label column
LABEL_COL = "label"

y = df[LABEL_COL]
X = df.drop(columns=[LABEL_COL])

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

# Lightweight model
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# Evaluation
y_pred = model.predict(X_test)
print("\n=== Classification Report ===\n")
print(classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "phishnet_light_model.pkl")
joblib.dump(list(X.columns), "feature_columns.pkl")

print("\n✅ Model saved successfully")
