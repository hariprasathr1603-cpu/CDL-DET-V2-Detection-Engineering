import pandas as pd

file_path = r"C:\Users\hari9\Datasets\mordor\Security-Datasets-master\datasets\atomic\windows\execution\host\empire_launcher_vbs\empire_launcher_vbs_2020-09-04160940.json"

df = pd.read_json(file_path, lines=True)

print("Total events:", len(df))
print("Columns:", list(df.columns))
print("\nEvent ID counts:")
print(df["EventID"].value_counts().head(10))
