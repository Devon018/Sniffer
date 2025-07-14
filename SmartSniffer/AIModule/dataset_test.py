import pandas as pd

df = pd.read_parquet("CIC-IDS2017/Network-Flows/CICIDS_Flow.parquet")

print(df.columns)
df.to_csv("CIC-IDS2017/Network-Flows/CICIDS_Flow.csv", index=False)