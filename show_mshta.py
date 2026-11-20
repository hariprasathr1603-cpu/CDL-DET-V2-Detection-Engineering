from pathlib import Path
lines = Path("rules/win_mshta_remote_or_script.yml").read_text(encoding="utf-8").splitlines()
for i, line in enumerate(lines, 1):
    print(f"{i:2d}: {line}")