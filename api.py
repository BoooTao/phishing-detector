from fastapi import FastAPI
from pydantic import BaseModel
import joblib
from predict import predict


MODEL_PATH = "models/phishing_rf_model.joblib"

app = FastAPI()
model = joblib.load(MODEL_PATH)

class URLRequest(BaseModel):
    url: str


@app.post("/predict")
def predict_endpoint(request: URLRequest):
    prediction, confidence = predict(request.url, model)
    return {
        "url": request.url,
        "prediction": str(prediction),
        "confidence": float(confidence),
    }

