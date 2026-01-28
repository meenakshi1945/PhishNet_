import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split
import joblib
import os


X = np.random.rand(1000,3).astype("float32") * np.array([200,5000,8])
y = (X[:,1] / (X[:,0]+1) > 20).astype(int)

X_train,X_test,y_train,y_test = train_test_split(X,y,test_size=0.2, random_state=42)

dtrain = lgb.Dataset(X_train, label=y_train)
params = {"objective":"binary","metric":"binary_logloss","verbose":-1}

bst = lgb.train(params, dtrain, num_boost_round=50)
os.makedirs("ml_model", exist_ok=True)
joblib.dump(bst, "ml_model/lgb_model.pkl")
print("Saved model to ml_model/lgb_model.pkl")
