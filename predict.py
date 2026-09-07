import sys
import joblib
import pandas as pd
from main import extract, FEATURE_COLS

MODEL_PATH = "models/phishing_rf_model.joblib"


def predict(url, model):
    features = extract(url)
    row = pd.DataFrame([features])[FEATURE_COLS].astype(float)
    prediction = model.predict(row)[0]
    probs = model.predict_proba(row)[0]
    confidence = probs.max()
    breakdown = dict(zip(model.classes_, probs))
    return prediction, confidence, breakdown


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else input ("Enter URL: ")
    model = joblib.load(MODEL_PATH)

    prediction, confidence = predict(url, model)
    print(f"{url}\n -> {prediction} -> ({confidence * 100:.1f}% confidence")


if __name__ == "__main__":
    main()