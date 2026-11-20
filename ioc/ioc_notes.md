# Indicator of Compromise (IOC) Notes & Context  
  
| Indicator | Type | Context in Lab Dataset | Detection & Triage Use |  
| --- | --- | --- | --- |  
| C:\Users\pgustavo\Desktop\launcher.vbs | File Path / Script | Observed with wscript.exe in VBS launcher hunt/case (T1059.005) | Hunt and alert on script-host execution of launcher scripts |  
| wscript.exe / cscript.exe | Process / Script Host | Windows script hosts launching VBS payloads and child processes | Validate parent-child process trees and filter authorized admin tools |  
| whoami.exe | Process / Recon Binary | Spawning after execution/PowerShell activity during discovery (T1033) | Correlate with script/PowerShell parents to spot post-execution recon |  
| Missing/NaN CommandLine & ParentImage | Telemetry Indicator | Subset of rows lacking full command-line or parent fields | Flag blind spots for log enrichment and rule tuning (NaN telemetry) |  
