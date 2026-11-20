import pandas as pd

file_path = r"C:\Users\hari9\Datasets\mordor\Security-Datasets-master\datasets\atomic\windows\execution\host\empire_launcher_vbs\empire_launcher_vbs_2020-09-04160940.json"
df = pd.read_json(file_path, lines=True)

if "EventID" in df.columns:
    proc = df[df["EventID"] == 1]
    print("Sysmon EventID 1 (Process Create) count:", len(proc))
    for col in ["Image", "CommandLine", "ParentImage"]:
        if col in proc.columns:
            print(f"\n--- Top {col} ---")
            print(proc[col].dropna().value_counts().head(5))
