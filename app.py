from flask import Flask, request, render_template
import numpy as np
import pickle
from feature import FeatureExtraction
from xgboost import XGBClassifier

app = Flask(__name__)

# ✅ Load trained model
try:
    with open("pickle/model.pkl", "rb") as file:
        model = pickle.load(file)

    if not isinstance(model, XGBClassifier):
        raise ValueError("Loaded model is not an XGBoost Classifier. Retraining may be required.")
except Exception as e:
    raise RuntimeError(f"Error loading model: {e}")

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        obj = FeatureExtraction(url)
        features = obj.get_features()
        
        prediction = model.predict([features])[0]
        probability = model.predict_proba([features])[0][1]

        # ✅ Adjust confidence threshold
        threshold = 0.4  # Lower threshold to detect phishing more accurately
        if probability > threshold:
            result = "Website is UNSAFE to use!"
            risk = f"Risk Level: {probability * 100:.2f}%"
        else:
            result = "Website is SAFE to use."
            risk = f"Confidence: {100 - (probability * 100):.2f}%"

        return render_template("index.html", prediction=result, risk=risk, url=url, xx=probability)

    # ✅ If it's a GET request (initial page load), define default values
    return render_template("index.html", prediction="", risk="", url="", xx=0)

if __name__ == "__main__":
    app.run(debug=True)
