from pathlib import Path
import uuid
from sigma.rule import SigmaRule
content = '''title: Mshta Executing HTA or Script Payload
id: ''' + str(uuid.uuid4()) + '''
status: experimental
description: Detects mshta.exe executing HTA files, scripts, or remote URLs
references:
  - https://attack.mitre.org/techniques/T1218/005
author: Detection Engineering Lab
date: 2026/11/20
tags:
  - attack.t1218.005
logsource:
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith: \\mshta.exe
    CommandLine|contains:
      - http
      - javascript:
      - vbscript:
      - .hta
  condition: selection
falsepositives:
  - Legitimate administrative HTA scripts
level: high
'''
p = Path('rules/win_mshta_remote_or_script.yml')
p.write_text(content, encoding='utf-8')
SigmaRule.from_yaml(np.read_text(encoding='utf-8'))
print('FIXED AND VERIFIED:', p.name)
