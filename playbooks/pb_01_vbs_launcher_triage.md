# Playbook 01: Suspicious VBS Launcher Triage - MITRE T1059.005

## Telemetry & Key Fields
- Check EventID (1 / 4688), Image, CommandLine, ParentImage, and User.
- Check wscript.exe and cscript.exe command lines for .vbs execution.

## Triage & Investigation
- Inspect parent process such as explorer.exe and verify script origin.
- Check whether the .vbs file came from a temporary, downloads, user, or network path.
- Review any child processes spawned (such as powershell.exe, cmd.exe, mshta.exe, or rundll32.exe) and any follow-on network or registry changes.

## Containment & Escalation
- Isolate the host or stop suspicious script/child processes if malicious activity is confirmed.
- Escalate confirmed incidents with timestamps, host/user details, command lines, and file hashes.
## Trigger Conditions
- Alert or detection triggered by suspicious VBScript launcher execution (`wscript.exe` / `cscript.exe` launching `.vbs` scripts, especially from user, temp, or downloads directories).

## Eradication & Recovery
- Remove malicious `.vbs` scripts and associated artifacts after preserving evidence.
- Verify persistence mechanisms (Run keys, scheduled tasks, services) are clean and restore normal system operations.

## Stakeholder Communications
- Notify SOC lead / incident response lead immediately upon confirming malicious script execution.
- Provide affected host, username, timestamp, MITRE ATT&CK technique (`T1059.005`), and containment status to stakeholders.
-