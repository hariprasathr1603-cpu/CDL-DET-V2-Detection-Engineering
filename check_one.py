from pathlib import Path
from sigma.rule import SigmaRule
for p in sorted(Path('rules').rglob('*.yml')):
    try:
        SigmaRule.from_yaml(p.read_text(encoding='utf-8'))
    except Exception as e:
        print(p.name, '-->', type(e).__name__, ':', e)
