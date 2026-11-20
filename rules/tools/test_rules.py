from pathlib import Path
import yaml

rules = sorted(Path("rules").rglob("*.yml"))
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

print(f"{'Rule':<36} | {'Technique ID':<14} | {'Events Scanned':<14} | {'Matches':<7}")
print("-" * 80)

for r in rules:
    y = yaml.safe_load(r.read_text(encoding="utf-8")) or {}
    tids = ", ".join(
        t.replace("attack.", "").upper()
        for t in (y.get("tags") or [])
        if isinstance(t, str) and t.startswith("attack.t")
    ) or "N/A"

    terms = []

    def grab(o):
        if isinstance(o, str):
            val = o.strip()
            if val and not val.isdigit() and len(val) > 1:
                terms.append(val.lower())
        elif isinstance(o, list):
            for x in o:
                grab(x)
        elif isinstance(o, dict):
            for k, v in o.items():
               if str(k).lower() not in ("eventid", "condition"):
                    grab(v)

    grab(y.get("detection"))
    matches = sum(1 for ln in lines if any(t in ln.lower() for t in terms)) if lines and terms else 0
    print(f"{r.stem:<36} | {tids:<14} | {len(lines):<14} | {matches:<7}")
    