from pathlib import Path
import traceback
from sigma.rule import SigmaRule
for p in sorted(Path('rules').rglob('*.yml')):
    try:
        SigmaRule.from_yaml(p.read_text(encoding='utf-8'))
    except Exception:
        print('FILE:', p)
        traceback.print_exc()
