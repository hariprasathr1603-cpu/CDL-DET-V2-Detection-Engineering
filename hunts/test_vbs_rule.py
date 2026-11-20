import pandas as pd

file_path = r"C:\Users\hari9\Datasets\mordor\Security-Datasets-master\datasets\atomic\windows\execution\host\empire_launcher_vbs\empire_launcher_vbs_2020-09-04160940.json"
df = pd.read_json(file_path, lines=True)

cols = [c for c in ["EventID", "Image", "CommandLine", "ParentImage"] if c in df.columns]

if "CommandLine" in df.columns:
    vbs_hits = df[df["CommandLine"].astype(str).str.contains("vbs|wscript|cscript", case=False, na=False)]
    print("Matching CommandLine rows:", len(vbs_hits))
    if len(vbs_hits) > 0:
        print(vbs_hits[cols].head(10).to_string())

if "Image" in df.columns:
    host_hits = df[df["Image"].astype(str).str.contains("wscript.exe|cscript.exe", case=False, na=False)]
    print("\nMatching Image rows (wscript/cscript):", len(host_hits))
    if len(host_hits) > 0:
        print(host_hits[cols].head(10).to_string())
