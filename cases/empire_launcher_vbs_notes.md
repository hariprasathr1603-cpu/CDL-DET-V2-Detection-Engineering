# Case Notes: Empire Launcher VBS

- **Dataset:** empire_launcher_vbs_2020-09-04160940.json
- **Rule Created:** 
ules/win_suspicious_vbs_launcher.yml (MITRE ATT&CK T1059.005)
- **Key Observations:**
  - Reviewed top Event IDs and process creation (EventID 1) parent/child relationships.
  - Checked wscript.exe / cscript.exe and .vbs command-line patterns for detection coverage and false positives.

- **Post-Execution Recon (EventID 1):** Observed powershell.exe spawning whoami.exe, indicating discovery activity following script execution.
- **Additional Rule Added:** 
ules/win_suspicious_ps_recon.yml (MITRE ATT&CK T1033).
  
  
## Case 2 Timeline: WScript Launcher & Incomplete Telemetry  
- **Step 1 (Script Host Execution):** wscript.exe invoked with C:\Users\pgustavo\Desktop\launcher.vbs (MITRE ATT&CK T1059.005).  
- **Step 2 (Telemetry Gap / Inconclusive Fields):** Follow-on events showed missing/NaN CommandLine and ParentImage values in subset rows.  
- **Closure Classification:** Inconclusive / Needs Enrichment (suspicious VBS launcher observed; incomplete parent/command-line telemetry on secondary rows).  
## Raw Log Timeline & MITRE ATT&CK Mapping
- `[Timestamp from log]` | Source/EventID: `Sysmon EventID 1` | Raw Log / Key Fields: `Image=wscript.exe, CommandLine=wscript.exe C:\Users\pgustavo\Desktop\launcher.vbs, ParentImage=explorer.exe` | Technique: `T1059.005`
- `[Timestamp from log]` | Source/EventID: `Sysmon EventID 1` | Raw Log / Key Fields: `Image=whoami.exe, ParentImage=powershell.exe` | Technique: `T1033`

## MITRE ATT&CK Techniques Involved
- `T1059.005` (Command and Scripting Interpreter: Visual Basic)
- `T1033` (System Owner/User Discovery)

## Root Cause Analysis
- Script host execution (`wscript.exe`) ran `launcher.vbs` from the Desktop path followed by `whoami.exe` discovery via `powershell.exe`, while missing/NaN `CommandLine` and `ParentImage` values on secondary subset rows reduced full visibility across follow-on activity.

## Impact Assessment
- Script execution and discovery activity occurred on the observed host, and incomplete fields on secondary events created a visibility gap requiring log enrichment.

## Closure Classification
- **Classification:** True Positive (or Benign Positive / False Positive — update based on your verified log evidence)
- **Justification:** Corroborated by observed `wscript.exe` / `.vbs` execution and discovery process activity in the dataset logs; telemetry gaps on subset rows were also documented for enrichment.
-