# Lab Report: Ransomware Detection and Incident Response

## Question

Can multiple weak-to-strong Windows telemetry signals be correlated into a high-confidence ransomware incident while routine administrative activity remains below the escalation threshold?

## Hypothesis

A synthetic attack dataset containing execution, credential access, lateral movement, defense evasion, recovery inhibition, and encryption-impact evidence will produce a critical incident. A benign administrative control dataset will produce no detections.

## Materials

- Python 3.10 or later
- Sanitized synthetic attack telemetry in JSONL format
- Sanitized benign control telemetry
- Python `unittest`

## Variables

- Independent variable: telemetry sequence supplied to the analyzer.
- Dependent variables: rule detections, ATT&CK techniques, severity, confidence, and response recommendations.
- Controls: identical parsing, detection rules, file-burst threshold, correlation model, and reporting process for both datasets.

## Procedure

1. Constructed a synthetic Windows/Sysmon-style attack timeline without executing any represented command.
2. Implemented seven deterministic detection rules mapped to six MITRE ATT&CK techniques.
3. Required at least five unique encrypted-file writes within 60 seconds for file-impact detection.
4. Correlated the impact finding with at least four distinct techniques before declaring critical severity.
5. Generated an incident timeline, containment guidance, and recovery checklist.
6. Repeated the experiment with routine PowerShell, SMB, file-write, and shadow-listing activity.
7. Ran unit tests, repository-policy tests, Bandit, and CodeQL.

## Results

The attack dataset generated seven findings across six techniques and two affected hosts. It met the critical-severity and high-confidence thresholds. The benign dataset generated zero findings and remained informational.

| Measurement | Attack dataset | Benign control |
| --- | ---: | ---: |
| Detection findings | 7 | 0 |
| Distinct ATT&CK techniques | 6 | 0 |
| Affected hosts | 2 | 0 |
| Severity | Critical | Informational |
| Confidence | High | Low |

## Interpretation

The observed result supports the hypothesis for the controlled datasets. Correlation reduced reliance on any single indicator: critical classification required both file-impact activity and evidence from several other attack stages.

## Limitations

- All telemetry is synthetic and does not represent a real organization.
- The rules are deterministic examples, not vendor-certified detections.
- The lab does not validate digital signatures, enrich hashes, query EDR platforms, or collect memory.
- Legitimate security tools may access LSASS or install services, so production use requires allowlists and environment-specific baselining.
- ATT&CK mappings describe modeled behavior and do not prove attribution.

## Conclusion

Multi-stage correlation successfully separated the modeled ransomware incident from the benign control. In production, these analytics should feed an approved case-management process with asset context, identity enrichment, evidence retention, and human authorization for containment.
