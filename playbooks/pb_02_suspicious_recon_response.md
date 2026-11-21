## Trigger Conditions
- Alert or detection triggered by post-execution discovery/reconnaissance activity (such as `whoami.exe` or discovery commands spawned from `powershell.exe`, script hosts, or unusual parent processes mapped to `MITRE T1033`).

## Investigation Steps
- Inspect `powershell.exe` or script hosts spawning `whoami.exe` and review surrounding process creation events (`EventID 1` / `4688`), `Image`, `CommandLine`, `ParentImage`, and `User`.
- Correlate user context, host activity, and the surrounding process tree to see if reconnaissance followed suspicious script/launcher execution or unauthorized access.

## Containment Steps
- Isolate the affected host or terminate unauthorized/suspicious script or shell processes if malicious reconnaissance is confirmed.
- Block or restrict compromised user/session activity while preserving evidence.

## Eradication & Recovery
- Remove unauthorized scripts, payloads, or persistence artifacts and verify clean system state.
- Restore normal operations and monitor the host for follow-on lateral movement or credential access.

## Stakeholder Communications
- Escalate confirmed malicious reconnaissance to the SOC lead / incident response lead with timestamps, host/user details, command lines, and `MITRE T1033` context.
- Provide status updates to relevant stakeholders when containment and recovery milestones are reached.
-