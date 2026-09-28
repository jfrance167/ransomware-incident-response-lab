# Ransomware Incident Analysis

> Educational analysis of sanitized, synthetic telemetry. No malware or destructive command was executed.

Source: `ransomware-attack.jsonl`

Incident severity: **CRITICAL**
Analytic confidence: **HIGH**
Detections: **7**
Affected hosts: **FS-01, WS-042**

## Executive assessment

The correlated evidence is consistent with a multi-stage ransomware incident that reached data-impact activity. Immediate containment and credential-risk review are warranted in the modeled scenario.

## Detection timeline

| Time (UTC) | Host | Rule | Severity | ATT&CK | Evidence |
| --- | --- | --- | --- | --- | --- |
| 2026-09-28T13:00:08+00:00 | WS-042 | RANSOM-001: Encoded PowerShell execution | High | T1059.001 | process=powershell.exe; option=encoded-command |
| 2026-09-28T13:01:04+00:00 | WS-042 | RANSOM-002: Suspicious LSASS process access | Critical | T1003.001 | source=lab-agent.exe; target=lsass.exe; access=0x1010 |
| 2026-09-28T13:02:10+00:00 | FS-01 | RANSOM-003: Remote service lateral movement | High | T1021.002 | service=psexesvc; remote-path-observed=true |
| 2026-09-28T13:03:00+00:00 | FS-01 | RANSOM-004: System recovery inhibited | Critical | T1490 | process=vssadmin.exe; recovery-modification=true |
| 2026-09-28T13:03:08+00:00 | FS-01 | RANSOM-005: Windows audit log cleared | High | T1070.001 | event_id=1102; channel=Security |
| 2026-09-28T13:04:20+00:00 | FS-01 | RANSOM-006: Rapid encrypted-file modification burst | Critical | T1486 | unique_files=5; window_seconds=60 |
| 2026-09-28T13:04:24+00:00 | FS-01 | RANSOM-007: Ransom-note artifact created | Critical | T1486 | file=readme_restore.txt |

## MITRE ATT&CK coverage

- `T1003.001`
- `T1021.002`
- `T1059.001`
- `T1070.001`
- `T1486`
- `T1490`

## Recommended response

1. Isolate affected hosts through approved EDR or network controls while preserving volatile evidence.
2. Disable or reset potentially exposed accounts and review privileged authentication from the affected hosts.
3. Restrict SMB/admin-share lateral movement and hunt for the same service artifact across peer systems.
4. Protect offline backups and validate recovery media before beginning restoration.
5. Preserve encrypted samples and ransom notes; restore only after eradication and clean-host validation.
6. Retain the synthetic timeline, detection evidence, and analyst decisions for lessons learned.

## Recovery validation checklist

- Confirm the initial access path is closed.
- Confirm persistence and remote-service artifacts are removed.
- Validate privileged credentials were rotated where exposure was plausible.
- Restore from known-good backups to isolated systems first.
- Monitor restored systems for recurrence before returning them to production networks.
