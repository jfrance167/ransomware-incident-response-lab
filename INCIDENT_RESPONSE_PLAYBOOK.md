# Ransomware Incident Response Playbook

This playbook is an educational decision aid. Follow organizational authorization, legal, privacy, safety, and evidence-handling requirements.

## 1. Validate

- Confirm timestamps, host identity, user context, and sensor health.
- Determine whether administration or security tooling explains the activity.
- Preserve original telemetry and record the analyst's decision.

## 2. Contain

- Isolate confirmed affected hosts through approved EDR or network controls.
- Protect backup infrastructure and restrict lateral-movement paths.
- Disable or reset exposed accounts according to identity-response procedures.
- Do not power off systems when volatile evidence is required unless safety demands it.

## 3. Investigate

- Reconstruct the process tree and initial-access path.
- Hunt for the same service, account, destination, and encrypted extension across the environment.
- Capture memory or forensic images only with approved tooling and authority.
- Establish incident scope before broad recovery.

## 4. Eradicate and recover

- Remove persistence and close the initial-access path.
- Rebuild from known-good media where integrity is uncertain.
- Restore validated backups to isolated systems first.
- Monitor restored systems before reconnecting them to production networks.

## 5. Close

- Document the timeline, decisions, evidence, business impact, and control gaps.
- Convert confirmed gaps into owned remediation items.
- Tune detections using reviewed false positives and missed evidence.
