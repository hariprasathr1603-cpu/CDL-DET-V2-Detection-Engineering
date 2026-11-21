
# Log Telemetry Data Dictionary

## Windows Security / Sysmon EVTX Fields

| Field | Source | Detection Meaning |
| :--- | :--- | :--- |
| EventID | System / EventData | Identifies the specific Windows Security or Sysmon event type (e.g., process creation, logon, script activity). |
| Image | EventData (Sysmon 1) | Full path to the executable binary that was launched. |
| CommandLine | EventData (Sysmon 1) | Full command-line arguments passed to the process at execution. |
| ParentImage | EventData (Sysmon 1) | Full path to the parent process that spawned the child process. |
| User | EventData (Sysmon 1) | Account context (DOMAIN\User) under which the process ran. |

