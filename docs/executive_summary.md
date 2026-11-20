# Executive Summary: VBS Launcher & Post-Execution Recon Detection  
  
## What This Project Does  
This detection engineering project analyzes Windows process and script execution logs to detect suspicious Visual Basic script (VBS) launchers and follow-up reconnaissance activity.  
  
## Key Findings  
- **Suspicious Script Execution (MITRE T1059.005):** Detected script-host activity such as wscript.exe running launcher.vbs.  
- **Post-Execution Discovery (MITRE T1033):** Identified follow-on reconnaissance behavior such as powershell.exe spawning whoami.exe.  
- **Telemetry Gaps:** Flagged rows with missing or NaN command-line and parent-process fields so rules and logging can be improved.  
  
## Response Readiness  
Built step-by-step triage playbooks (pb_01 to pb_03) and an IOC reference table with context and detection/triage use.  
