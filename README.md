# CDL-DET-V2 Detection Engineering

Hands-on detection engineering project analyzing Mordor's empire_launcher_vbs dataset with Python (Pandas), authoring a Sigma detection rule (T1059.005), and tracking work with Git.

## Project Structure
- docs/data_dictionary.md — Key Windows/Sysmon log fields referenced during analysis
- hunts/explore_logs.py — Initial dataset exploration and Event ID counts
- hunts/hunt_empire_vbs.py — Sysmon process creation (EventID 1) analysis (Image, CommandLine, ParentImage)
- hunts/test_vbs_rule.py — Validation script checking VBS / script host matches
- ules/win_suspicious_vbs_launcher.yml — Sigma rule for suspicious VBScript execution via wscript.exe / cscript.exe
- cases/empire_launcher_vbs_notes.md — Investigation notes and findings
