## Trigger Conditions
- Detection or log quality check identifies missing, null, or `NaN` fields (such as `CommandLine` or `ParentImage`) or blind spots in required telemetry sources/event IDs.

## Investigation Steps
- Identify events with null or `NaN` `CommandLine` or `ParentImage` fields and check which hosts, log sources, or event IDs are affected.
- Verify which detection rules or correlation rules lose visibility when those fields are missing.

## Containment Steps
- Flag affected hosts or log pipelines as having degraded detection visibility and apply compensating monitoring/hunting checks where telemetry is incomplete.
- Prioritize high-risk or incident-involved hosts for closer manual review until logging is restored.

## Eradication & Recovery
- Enable or verify detailed process creation logging (such as Sysmon / Security auditing and full command-line logging) and fix log collection/parsing issues.
- Re-test affected detection rules and confirm required fields populate cleanly across new events.

## Stakeholder Communications
- Notify the SOC lead and detection/telemetry owners of confirmed blind spots, affected hosts/rules, and enrichment progress.
- Report once telemetry completeness is verified and detection coverage is restored.
-