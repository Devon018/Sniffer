import joblib
import os
import numpy as np

MODEL_PATH = "model/model.pkl" # Path to the model file

class ModelLoader:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.protocol_encoder = None
        self.load_model()

    def load_model(self):
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError("Model file not found.")
        self.model = joblib.load("model/model.pkl")
        self.scaler = joblib.load("model/scaler.pkl")
        self.label_encoder = joblib.load("model/label_encoder.pkl")
        self.protocol_encoder = joblib.load("model/protocol_encoder.pkl")

    def get_model(self):
        return self.model, self.scaler, self.label_encoder, self.protocol_encoder