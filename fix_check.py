from pathlib import Path
import yaml
from sigma.rule import SigmaRule

for p in sorted(Path("rules").glob("*.yml")):
    try:
        SigmaRule.from_yaml(p.read_text(encoding="utf-8"))
    except Exception as e:
        print("FAIL:", p.name, "->", type(e).__name__, e)
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        print("YAML:", data)
