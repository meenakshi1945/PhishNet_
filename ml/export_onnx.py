import numpy as np
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import joblib
from pathlib import Path

p = Path("ml_model/lgb_model.pkl")
if not p.exists():
    print("Train first: python train.py")
else:
    bst = joblib.load(str(p))
    
    from sklearn.linear_model import LogisticRegression
    X = np.random.rand(100,3).astype("float32")
    y = (X[:,1] > 0.5).astype(int)
    clf = LogisticRegression().fit(X, y)
    onx = convert_sklearn(clf, "phishnet_demo", initial_types=[('input', FloatTensorType([None,3]))])
    with open("../backend/app/models/sample_model.onnx", "wb") as f:
        f.write(onx.SerializeToString())
    print("Exported demo ONNX")
