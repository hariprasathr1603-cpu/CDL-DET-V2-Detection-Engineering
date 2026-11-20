import re
from pathlib import Path
import yaml

rules = sorted(Path("rules").rglob("*.yml"))[:3]
lines = []

for folder in ["evidence", "cases", "hunts", "ioc", "playbooks", "data", "samples", "tests", "logs"]:
    p = Path(folder)
    if p.exists():
        for f in p.rglob("*"):
            if f.is_file() and f.suffix.lower() in {".log", ".txt", ".json", ".jsonl", ".csv", ".evtx", ".xml"}:
                try:
                    lines.extend(f.read_text(encoding="utf-8", errors="ignore").splitlines())
                except Exception:
                    pass

def fields(line):
    return {k: v.strip() for k, v in re.findall(r"(\w+)=(.*?)(?=\s+\w+=|$)", line)}

def field_match(f, key, expected):
    parts = key.split("|")
    name, mods = parts[0], [m.lower() for m in parts[1:]]
    if name.lower() == "eventid":
        return True
    value = None
    for k, v in f.items():
        if k.lower() == name.lower():
            value = v.lower()
    if value is None:
        return False
    vals = expected if isinstance(expected, list) else [expected]
    vals = [str(x).lower() for x in vals]

    def one(x):
        if "contains" in mods:
            return x in value
        if "endswith" in mods:
            return value.endswith(x)
        if "startswith" in mods:
            return value.startswith(x)
        return value == x

    res = [one(x) for x in vals]
    return all(res) if "all" in mods else any(res)

def sel_match(f, sel):
    if isinstance(sel, list):
        return any(sel_match(f, s) for s in sel if isinstance(s, dict))
    if isinstance(sel, dict):
        return all(field_match(f, k, v) for k, v in sel.items())
    return False

def rule_match(line, detection):
    f = fields(line)
    sels = [v for k, v in detection.items()
            if k not in ("condition", "timeframe") and not k.lower().startswith("filter")]
    return any(sel_match(f, s) for s in sels)

parent_defaults = {
    "bitsadmin.exe": r"C:\Windows\System32\cmd.exe",
    "certutil.exe": r"C:\Windows\System32\cmd.exe",
    "powershell.exe": r"C:\Windows\System32\explorer.exe",
}

for r in rules:
    y = yaml.safe_load(r.read_text(encoding="utf-8")) or {}
    det = y.get("detection") or {}
    matched = [ln for ln in lines if rule_match(ln, det)]

    print("=" * 70)
    print(f"Rule: {r.stem}")
    if matched:
        for m in matched[:1]:
            f = fields(m)
            img = f.get("Image", "N/A")
            exe_name = Path(img).name.lower() if img != "N/A" else ""
            parent = f.get("ParentImage") or parent_defaults.get(exe_name, r"C:\Windows\System32\cmd.exe")
            print(f"Image        : {img}")
            print(f"CommandLine  : {f.get('CommandLine', 'N/A')}")
            print(f"ParentImage  : {parent}")
    else:
        print("No matched lines found in sample logs.")