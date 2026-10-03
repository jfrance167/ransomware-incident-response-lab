# Ransomware Detection and Incident Response Lab

This defensive-security lab detects and correlates a modeled ransomware attack chain using sanitized, synthetic Windows telemetry. It does not contain malware, execute commands from the telemetry, connect to endpoints, or modify system files.

## Synthetic terminal example

Run the included ransomware scenario, which consists of inert JSONL telemetry. This excerpt shows the actual CLI summary with host identifiers omitted.

```text
$ python ransomware_ir.py samples/ransomware-attack.jsonl
# Ransomware Incident Analysis
Incident severity: **CRITICAL**
Analytic confidence: **HIGH**
Detections: **7**
Affected hosts: **[synthetic hosts omitted]**
```

## Detection coverage

| Rule | Behavior | MITRE ATT&CK |
| --- | --- | --- |
| RANSOM-001 | Encoded PowerShell | T1059.001 |
| RANSOM-002 | Suspicious LSASS access | T1003.001 |
| RANSOM-003 | Remote-service lateral movement | T1021.002 |
| RANSOM-004 | Recovery inhibition | T1490 |
| RANSOM-005 | Windows audit-log clearing | T1070.001 |
| RANSOM-006 | Rapid encrypted-file burst | T1486 |
| RANSOM-007 | Ransom-note creation | T1486 |

## Run the lab

Python 3.10 or later is required; there are no runtime dependencies.

```bash
python ransomware_ir.py samples/ransomware-attack.jsonl --output reports/ransomware-incident-report.md
python ransomware_ir.py samples/benign-control.jsonl --output reports/benign-control-report.md --fail-on-incident
python -m unittest discover -s tests -v
```

Use `--format json` for machine-readable output. With `--fail-on-incident`, the program returns exit status 1 only for high or critical correlated incidents.

Telemetry input is capped at 100 MiB total, 1 MiB per JSONL line, and 100,000
events. Markdown report fields are escaped and web, FTP, and email URL schemes
are defanged; JSON output retains the original parsed values.

## Evidence

- [`LAB_REPORT.md`](LAB_REPORT.md) records the hypothesis, procedure, measured results, limitations, and conclusion.
- [`reports/ransomware-incident-report.md`](reports/ransomware-incident-report.md) contains the generated attack-chain investigation.
- [`reports/benign-control-report.md`](reports/benign-control-report.md) demonstrates that ordinary administrative activity remains quiet.
- [`INCIDENT_RESPONSE_PLAYBOOK.md`](INCIDENT_RESPONSE_PLAYBOOK.md) provides a safe analyst decision framework.

## Safety and scope

All commands, paths, hosts, users, addresses, and artifacts in `samples/` are inert data created for this lab. Documentation-reserved IP space and fictional identities are used. The analyzer only parses local JSONL and never passes telemetry fields to a shell or process launcher.

## Repository map

```text
ransomware-incident-response-lab/
|-- .github/
|-- .gitignore
|-- INCIDENT_RESPONSE_PLAYBOOK.md
|-- LAB_REPORT.md
|-- README.md
|-- SECURITY.md
|-- ransomware_ir.py
|-- reports/
|-- samples/
`-- tests/
```

Follow the setup and safety boundaries above before running or deploying any code.
