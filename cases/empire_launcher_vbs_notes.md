# Case Notes: Empire Launcher VBS

- **Dataset:** empire_launcher_vbs_2020-09-04160940.json
- **Rule Created:** ules/win_suspicious_vbs_launcher.yml (MITRE ATT&CK T1059.005)
- **Key Observations:**
  - Reviewed top Event IDs and process creation (EventID 1) parent/child relationships.
  - Checked wscript.exe / cscript.exe and .vbs command-line patterns for detection coverage and false positives.

- **Post-Execution Recon (EventID 1):** Observed powershell.exe spawning whoami.exe, indicating discovery activity following script execution.
- **Additional Rule Added:** ules/win_suspicious_ps_recon.yml (MITRE ATT&CK T1033).
