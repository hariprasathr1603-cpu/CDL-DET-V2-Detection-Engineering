# CDL-DET-V2 Detection Engineering

Hands-on detection engineering project analyzing Mordor's empire_launcher_vbs dataset with Python (Pandas), authoring a Sigma detection rule (T1059.005), and tracking work with Git.

## Project Structure
- docs/data_dictionary.md — Key Windows/Sysmon log fields referenced during analysis
- hunts/explore_logs.py — Initial dataset exploration and Event ID counts
- hunts/hunt_empire_vbs.py — Sysmon process creation (EventID 1) analysis (Image, CommandLine, ParentImage)
- hunts/test_vbs_rule.py — Validation script checking VBS / script host matches
- 
ules/win_suspicious_vbs_launcher.yml — Sigma rule for suspicious VBScript execution via wscript.exe / cscript.exe
- cases/empire_launcher_vbs_notes.md — Investigation notes and findings
# Cyberion-ThreatShield

A SOC detection engineering lab focused on telemetry generation, log analysis, and custom rule creation to detect encoded PowerShell execution using Wazuh, Sysmon, and the MITRE ATT&CK framework.

---

## Table of Contents
- [Project Overview](#project-overview)
- [Lab Architecture & Environment](#lab-architecture--environment)
- [Detection Engineering Methodology](#detection-engineering-methodology)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Implementation & Configuration](#implementation--configuration)
- [Proof of Detection](#proof-of-detection)

---

## Project Overview
**Cyberion-ThreatShield** is a hands-on detection engineering project designed to simulate and detect obfuscated command-line behavior. Threat actors frequently leverage encoded PowerShell to bypass signature-based endpoint controls. This project establishes an end-to-end telemetry pipeline to capture, parse, and alert on suspicious PowerShell execution patterns.

---

## Lab Architecture & Environment
* **SIEM / Central Collector:** Wazuh Server (Ubuntu Server VM hosted on Oracle VM VirtualBox)
* **Endpoint:** Windows 11 Target VM
* **Endpoint Monitoring:** Sysmon (System Monitor) configured for advanced process tracking
* **Log Transport:** Wazuh Windows Agent forwarding logs securely to the SIEM manager

---

## Detection Engineering Methodology
1. **Telemetry Collection:** Sysmon is deployed on the endpoint to capture high-fidelity process creation events (Event ID 1), including command-line arguments and parent-child process relationships.
2. **Attack Simulation:** Controlled test cases are executed using base64-encoded PowerShell strings to emulate adversary execution techniques.
3. **Log Ingestion & Parsing:** The Wazuh agent ships endpoint telemetry to the manager, where decoders normalize the log fields.
4. **Custom Rule Development:** Custom XML rules (`local_rules.xml`) are written to analyze command-line parameters, specifically flagging patterns associated with execution obfuscation.

---

## MITRE ATT&CK Mapping
* **Tactic:** Execution (`TA0002`)
* **Technique:** Command and Scripting Interpreter: PowerShell (`T1059.001`)

---

## Implementation & Configuration
*(Include code snippets or references to your custom configuration files here, such as snippets from your Wazuh `local_rules.xml` or Sysmon configuration).*

---

## Proof of Detection
*(Insert screenshots or exported log JSON outputs demonstrating the custom Wazuh alert triggering successfully in response to the simulated attack).*
