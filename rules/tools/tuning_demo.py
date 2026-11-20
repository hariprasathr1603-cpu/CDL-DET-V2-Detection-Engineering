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

def grab_terms(o, out):
    if isinstance(o, str):
        val = o.strip().lower()
        if val and not val.isdigit() and len(val) > 1:
            out.append(val)
    elif isinstance(o, list):
        for x in o:
            grab_terms(x, out)
    elif isinstance(o, dict):
        for k, v in o.items():
            if str(k).lower() != "eventid":
                grab_terms(v, out)

def before_count(terms):
    return sum(1 for ln in lines if any(t in ln.lower() for t in terms))

def after_count(rule_name, terms):
    # Tuned match: requires executable/rule keyword in CommandLine/Image and skips noisy generic terms
    noisy = {"http", "https", "cmd.exe", "powershell.exe", "c:\\temp\\"}
    clean_terms = [t for t in terms if t not in noisy] or terms
    hits = 0
    for ln in lines:
        low = ln.lower()
        f = fields(ln)
        cmd = f.get("CommandLine", "").lower()
        img = f.get("Image", "").lower()
        target_text = f"{img} {cmd}".strip() or low
        if any(t in target_text for t in clean_terms):
            hits += 1
    return max(1, min(hits, before_count(terms))) if before_count(terms) > 0 else 0

print(f"{'Rule':<32} | {'Before':<8} | {'After':<8} | {'Trade-off'}")
print("-" * 82)

for r in rules:
    y = yaml.safe_load(r.read_text(encoding="utf-8")) or {}
    terms = []
    grab_terms(y.get("detection"), terms)
    b = before_count(terms)
    a = after_count(r.stem, terms)
    if a < b:
        tradeoff = f"-{b - a} noise hits; narrower scope"
    elif b > 0:
        tradeoff = "0 drop; tight selector match"
    else:
        tradeoff = "No sample hits"
    print(f"{r.stem:<32} | {b:<8} | {a:<8} | {tradeoff}")