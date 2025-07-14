import numpy as np
import joblib
from model_loader import ModelLoader

class Predictor:
    def __init__(self):
        self.model_loader = ModelLoader()
        self.model, self.scaler, self.label_encoder, self.protocol_encoder = self.model_loader.get_model()
    def predict(self, packet_json):

        '''
        input:
            sample = {
                "source_port": 49188,
                "destination_port": 800,
                "protocol": "htp",  # 必须是训练中出现过的协议
                "Total Fwd Packets": 25746564557546,
                "Fwd Packet Length Mean": 6654600.0,
                "Flow IAT Mean": 425754.0，
                "timestamp": "2023-10-01T12:00:00Z",
                "source_ip": <>,
                destination_ip: <>

            }
        '''
        try:
            try:
                packet_json["protocol"] = self.protocol_encoder.transform([packet_json["protocol"]])[0]
            except ValueError as e:
                print("协议类型未在训练集中出现:", e)
                packet_json["protocol"] = 0  # fallback 编码

            # === 构造输入特征向量并归一化 ===
            X = np.array([
                packet_json["source_port"],
                packet_json["destination_port"],
                packet_json["protocol"],
                packet_json["Total Fwd Packets"],
                packet_json["Fwd Packet Length Mean"],
                packet_json["Flow IAT Mean"]
            ]).reshape(1, -1)

            X_scaled = self.scaler.transform(X)

            # === 模型推理 ===
            pred = self.model.predict(X_scaled)[0]
            pred_label = self.label_encoder.inverse_transform([pred])[0]
            return {
                    "timestamp": packet_json.get("timestamp"),
                    "src_ip": packet_json.get("source_ip"),
                    "dst_ip": packet_json.get("destination_ip"),
                    "category": pred_label,
                }
            return None
        except Exception as e:
            return {"error": str(e)}
