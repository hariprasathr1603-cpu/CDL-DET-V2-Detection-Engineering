# Detection Engineering Methodology

## Datasets & Telemetry Sources
- **Datasets Used:** `empire_launcher_vbs_2020-09-04160940.json`, Windows/Sysmon/Security logs, Linux authentication logs, and attack sample datasets (`EVTX-ATTACK-SAMPLES` / test telemetry).
- **Telemetry & Key Fields:** Process creation and system/authentication events (`EventID 1` / `4688`, `Image`, `CommandLine`, `ParentImage`, `User`, and related telemetry mapped in `docs/data_dictionary.md`).

## Telemetry Collection, Normalization & Validation
- Loaded and inspected raw event logs and JSON datasets using Python scripts and tools in the repository (`tools/show_fields.py`, `rules/tools/test_rules.py`, `rules/tools/test_correlation.py`, `rules/tools/show_matches.py`, `rules/tools/coverage_summary.py`, and `rules/tools/tuning_demo.py`).
- Checked field completeness (including identifying null or `NaN` `CommandLine` and `ParentImage` fields), mapped detections to MITRE ATT&CK techniques, validated Sigma detection rules and correlation rules (`corr_01_script_to_recon.yml`, `corr_02_persistence_and_execution.yml`, `corr_03_credential_access_and_lateral.yml`), and documented findings in `hunts/`, `cases/`, `playbooks/`, and `docs/executive_summary.md`.
-