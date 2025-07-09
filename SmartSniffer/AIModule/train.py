import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os
from tqdm import tqdm

# 指定数据文件路径（请上传 CSV 后确认文件名）
csv_path = "CIC-IDS2017/Network-Flows/filtered_dataset.csv"  # 假设文件名为此，稍后会验证存在性
n_estimators = 200  # 随机森林树的数量
trees = []
# 检查文件是否存在
if not os.path.exists(csv_path):
    raise FileNotFoundError("请上传包含完整数据的 attack_dataset.csv 文件")

# 加载数据
df = pd.read_csv(csv_path)

# 清理无效或缺失数据
df.replace([np.inf, -np.inf], 0, inplace=True)
df.dropna(inplace=True)

# 协议编码
df['protocol'] = LabelEncoder().fit_transform(df['protocol'])

# 标签编码（统一 Benign 格式）
df['attack_label'] = df['attack_label'].apply(lambda x: 'Benign' if str(x).upper() == 'BENIGN' else x)
label_encoder = LabelEncoder()
df['attack_label'] = label_encoder.fit_transform(df['attack_label'])

# 分离特征与标签
X = df.drop(columns=['attack_label'])
y = df['attack_label']

# 特征标准化
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 划分训练和测试集
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.3, random_state=42, stratify=y
)

print("[INFO] 开始训练随机森林模型...")
for i in tqdm(range(n_estimators), desc="Training Progress"):
    tree = RandomForestClassifier(n_estimators=1, warm_start=True, random_state=42+i)
    if i == 0:
        clf = tree
    else:
        clf.n_estimators += 1
    clf.fit(X_train, y_train)

# 模型评估
y_pred = clf.predict(X_test)
report = classification_report(y_test, y_pred, target_names=label_encoder.classes_, output_dict=True)

# 保存模型、标准器、标签器
model_dir = "model/"
os.makedirs(model_dir, exist_ok=True)
joblib.dump(clf, os.path.join(model_dir, "model.pkl"))
joblib.dump(scaler, os.path.join(model_dir, "scaler.pkl"))
joblib.dump(label_encoder, os.path.join(model_dir, "label_encoder.pkl"))

# 显示报告
result = pd.DataFrame(report).transpose()
