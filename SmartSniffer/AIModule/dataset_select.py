import pandas as pd
import os

# 路径配置
parquet_path = "CIC-IDS2017/Network-Flows/CICIDS_Flow.parquet"
# output_dir = "model"
# output_path = os.path.join(output_dir, "CIC-IDS2017/Network-Flows/filtered_dataset.csv")
output_path = "CIC-IDS2017/Network-Flows/filtered_dataset.csv"
# 创建输出目录
# os.makedirs(output_dir, exist_ok=True)

# 读取 parquet 数据
df = pd.read_parquet(parquet_path, engine="pyarrow")  # 或 engine="fastparquet"

# 选择需要的字段
fields = [
    'source_port', 'destination_port', 'protocol',
    'Total Fwd Packets', 'Fwd Packet Length Mean',
    'Flow IAT Mean', 'attack_label'
]
df_filtered = df[fields].dropna()

# 保存为 CSV
df_filtered.to_csv(output_path, index=False)

print(f"成功保存为: {output_path}")
