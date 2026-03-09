# PhishNet Lightweight ML Module

This module provides URL phishing detection with:
- Supervised classifier (regularized DecisionTree baseline)
- Deep URL heuristic layer
- Zero-day anomaly ensemble (IsolationForest + PCA reconstruction + token novelty)

## Current Data Flow
1. Merge labeled URL datasets into `urls.csv`.
2. Generate numeric feature dataset `features.csv`.
3. Train classifier + anomaly model.
4. Use `inference.py` for runtime scoring and explanations.

## Stage 1: Expand Dataset
Use the dataset merger utility:

```bash
python prepare_urls.py --sources data/source1.csv data/source2.csv --output urls.csv
```

Expected source columns:
- `url`
- One label column: `label` or `class` or `target` or `status`

Accepted labels:
- phishing: `1`, `phishing`, `malicious`, `bad`, `true`
- legitimate: `0`, `legitimate`, `benign`, `safe`, `false`

Optional balancing:

```bash
python prepare_urls.py --sources data/source1.csv data/source2.csv --max-per-class 50000
```

## Stage 2: Regenerate Features

```bash
python generate_features.py
```

For explicit files (train/holdout):

```bash
python generate_features.py --input urls_train.csv --output features_train.csv
python generate_features.py --input urls_holdout.csv --output features_holdout.csv
```

## Stage 3: Retrain Models

```bash
python train.py
```

With strict holdout evaluation:

```bash
python train.py --features features_train.csv --urls-csv urls_train.csv --holdout-features features_holdout.csv
```

Artifacts created:
- `phishnet_light_model.pkl`
- `feature_columns.pkl`
- `explainability_meta.pkl`
- `phishnet_zero_day_model.pkl`
- `phishnet_zero_day_pca_model.pkl`
- `zero_day_meta.pkl`

## Runtime Output Notes
`predict_url` now returns:
- `label`, `confidence`
- `risk_level`, `recommended_action`
- `zero_day_flag`, `zero_day_score`
- `anomaly_decision_score`, `anomaly_threshold`
- `analysis_tags`, `reasons`

## Important Limitation
The zero-day detector here is a baseline anomaly model. It improves unknown-pattern detection,
but it is not a full threat-intel system. Accuracy depends heavily on dataset size and freshness.

## Realistic Dataset Pipeline (Recommended)
Build train/holdout URL datasets with domain-grouped split (reduces leakage):

```bash
python build_realistic_dataset.py --sources data/source1.csv data/source2.csv --train-output urls_train.csv --holdout-output urls_holdout.csv --holdout-size 0.2
```
