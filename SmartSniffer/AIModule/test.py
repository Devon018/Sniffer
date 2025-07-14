import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder, StandardScaler

# 加载训练数据（和训练时一致）
csv_path = "CIC-IDS2017/Network-Flows/filtered_dataset.csv"
df = pd.read_csv(csv_path)

# 清理无效数据
df.replace([np.inf, -np.inf], 0, inplace=True)
df.dropna(inplace=True)

# 加载模型和工具
model = joblib.load("model/model.pkl")
scaler = joblib.load("model/scaler.pkl")
label_encoder = joblib.load("model/label_encoder.pkl")

protocol_encoder = LabelEncoder()
# 协议编码（重新编码以匹配训练）
df['protocol'] = protocol_encoder.fit_transform(df['protocol'])

# save protocol encoder
joblib.dump(protocol_encoder, "model/protocol_encoder.pkl")
# 标签编码
df['attack_label'] = df['attack_label'].apply(lambda x: 'Benign' if str(x).upper() == 'BENIGN' else x)
df['attack_label'] = label_encoder.transform(df['attack_label'])

# 分离特征与标签
X = df.drop(columns=['attack_label'])
y = df['attack_label']

# 特征标准化
X_scaled = scaler.transform(X)

# 模型预测并评估
y_pred = model.predict(X_scaled)
report = classification_report(y, y_pred, target_names=label_encoder.classes_, output_dict=True)

# 展示评估结果
pd.DataFrame(report).transpose()
print(report)