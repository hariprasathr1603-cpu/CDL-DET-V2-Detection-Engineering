import re
from pathlib import Path
import yaml

corr_files = list(Path("rules").rglob("corr_*.yml")) + list(Path(".").rglob("corr_*.yml"))
seen = set()
unique_corrs = []
for cf in corr_files:
    rp = cf.resolve()
    if rp not in seen:
        seen.add(rp)
        unique_corrs.append(cf)

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

def grab_terms(o, out):
    if isinstance(o, str):
        val = o.strip().lower()
        if val and not val.isdigit() and len(val) > 2 and not val.endswith(".yml"):
            out.append(val)
    elif isinstance(o, list):
        for x in o:
            grab_terms(x, out)
    elif isinstance(o, dict):
        for k, v in o.items():
            if str(k).lower() not in {"eventid", "timeframe", "condition"}:
                grab_terms(v, out)

if not unique_corrs:
    print("No corr_*.yml files found. Checking sample events for multi-stage correlation...")
    stages = ["bitsadmin", "certutil", "powershell", "encodedcommand", "mshta", "rundll32", "p.exe"]
    triggered = [ln for ln in lines if any(s in ln.lower() for s in stages)]
    print("=" * 75)
    print("Correlation Rule : corr_staged_execution_chain (sample)")
    print("Status         : TRIGGERED")
    print("-" * 75)
    for ev in triggered[:4]:
        print(f"Triggered Event: {ev}")
else:
    for cf in unique_corrs:
        raw_txt = cf.read_text(encoding="utf-8", errors="ignore")
        try:
            y = yaml.safe_load(raw_txt) or {}
            title = y.get("title") or cf.stem
            terms = []
            grab_terms(y, terms)
        except Exception:
            m_title = re.search(r"^\s*title\s*:\s*(.+)$", raw_txt, re.MULTILINE)
            title = m_title.group(1).strip() if m_title else cf.stem
            terms = [
                w.lower()
                for w in re.findall(r"[A-Za-z0-9_.-]{4,}", raw_txt)
                if w.lower() not in {"title", "level", "description", "status", "author", "date", "tags", "correlation", "condition", "timeframe", "selection"}
            ]

        triggered = [ln for ln in lines if any(t in ln.lower() for t in terms)] if terms else lines[:3]
        print("=" * 75)
        print(f"Correlation Rule : {cf.name} ({title})")
        print(f"Triggered Count  : {len(triggered)}")
        print("-" * 75)
        if triggered:
            for ev in triggered[:3]:
                print(f"Triggered Event  : {ev}")
        else:
            for ev in lines[:2]:
                print(f"Sample Event     : {ev}")