from pathlib import Path
from sigma.rule import SigmaRule

for p in sorted(Path("rules").rglob("*.yml")):
    try:
        SigmaRule.from_yaml(p.read_text(encoding="utf-8"))
        print("OK:", p.name)
    except Exception as e:
        print("ERR:", p.name, "->", type(e).__name__, e)