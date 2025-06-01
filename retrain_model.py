import pandas as pd
import numpy as np
import pickle
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# ✅ Load dataset
df = pd.read_csv("balanced_phishing.csv")  
df['class'] = df['class'].replace(-1, 0)  # Convert -1 (phishing) to 0 for binary classification

# ✅ Debugging: Print class distribution
print(df['class'].value_counts())  # Check balance of safe vs phishing sites

X = df.iloc[:, :-1]  # Features
y = df.iloc[:, -1]   # Target label

# ✅ Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ✅ Train the XGBoost model
model = XGBClassifier(
    n_estimators=500,  # More trees for better learning
    learning_rate=0.03,  # Lower learning rate for stability
    max_depth=8,  # More depth to better separate phishing vs safe
    scale_pos_weight=1,  # Adjusts for class imbalance
    use_label_encoder=False,
    eval_metric="logloss",
    random_state=42
)
model.fit(X_train, y_train)

# ✅ Evaluate model accuracy
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy:.4f}")

# ✅ Save the improved model
with open("pickle/model.pkl", "wb") as file:
    pickle.dump(model, file)

print("New XGBoost model saved successfully!")
