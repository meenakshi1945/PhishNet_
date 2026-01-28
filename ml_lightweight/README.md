# PhishNet – Lightweight ML Module

This module implements a lightweight, explainable phishing detection model
designed for fast inference and safe integration with the PhishNet application.

## Model
- Algorithm: Logistic Regression
- Reason: Fast, interpretable, low-resource
- Input: Feature-selected numeric indicators
- Output:
  - Phishing / Benign label
  - Confidence score
  - Human-readable reason codes

## Files
- features.py – URL feature extraction
- train.py – Model training pipeline
- inference.py – Runtime prediction + explainability
- phishnet_light_model.pkl – Trained model

## Usage
Train:
```bash
python train.py
