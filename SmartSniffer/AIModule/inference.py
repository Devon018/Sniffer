import joblib
import numpy as np

# === 加载模型和工具 ===
model = joblib.load("model/model.pkl")
scaler = joblib.load("model/scaler.pkl")
label_encoder = joblib.load("model/label_encoder.pkl")
protocol_encoder = joblib.load("model/protocol_encoder.pkl")

# === 模拟输入样本（你可以替换为任意实时数据） ===
sample = {
    "source_port": 49188,
    "destination_port": 800,
    "protocol": "htp",  # 必须是训练中出现过的协议
    "Total Fwd Packets": 25746564557546,
    "Fwd Packet Length Mean": 6654600.0,
    "Flow IAT Mean": 425754.0
}

# === 协议编码 ===
try:
    sample["protocol"] = protocol_encoder.transform([sample["protocol"]])[0]
except ValueError as e:
    print("协议类型未在训练集中出现:", e)
    sample["protocol"] = 0  # fallback 编码

# === 构造输入特征向量并归一化 ===
X = np.array([
    sample["source_port"],
    sample["destination_port"],
    sample["protocol"],
    sample["Total Fwd Packets"],
    sample["Fwd Packet Length Mean"],
    sample["Flow IAT Mean"]
]).reshape(1, -1)

X_scaled = scaler.transform(X)

# === 模型推理 ===
pred = model.predict(X_scaled)[0]
pred_label = label_encoder.inverse_transform([pred])[0]

print(f"预测结果: {pred_label}")
