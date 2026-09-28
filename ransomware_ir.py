#!/usr/bin/env python3
"""Detect and report a ransomware attack chain in sanitized Windows telemetry."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path, PureWindowsPath
from typing import Mapping, Sequence


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ATTACK_CHAIN_WINDOW_SECONDS = 15 * 60
ENCRYPTED_EXTENSIONS = {".encrypted", ".locked", ".crypt", ".enc"}
RANSOM_NOTE_NAMES = {"readme_restore.txt", "recover_files.txt", "how_to_decrypt.txt"}
SUSPICIOUS_LSASS_ACCESS = {"0x1010", "0x1410", "0x143a", "0x1fffff"}


class TelemetryError(ValueError):
    """Raised when telemetry does not satisfy the lab schema."""


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    event_id: int
    host: str
    user: str
    event_type: str
    details: Mapping[str, object]


@dataclass(frozen=True)
class Detection:
    rule_id: str
    title: str
    severity: str
    tactic: str
    technique_id: str
    host: str
    timestamp: datetime
    summary: str
    evidence: str


@dataclass(frozen=True)
class Incident:
    severity: str
    confidence: str
    findings: tuple[Detection, ...]
    affected_hosts: tuple[str, ...]
    techniques: tuple[str, ...]


def _required_text(record: Mapping[str, object], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise TelemetryError(f"{key} must be a non-empty string")
    return value.strip()


def parse_event(record: object, line_number: int) -> Event:
    if not isinstance(record, dict):
        raise TelemetryError(f"line {line_number}: event must be a JSON object")
    timestamp_text = _required_text(record, "timestamp")
    try:
        timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TelemetryError(f"line {line_number}: invalid ISO-8601 timestamp") from exc
    if timestamp.tzinfo is None:
        raise TelemetryError(f"line {line_number}: timestamp must include a timezone")
    event_id = record.get("event_id")
    if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 0:
        raise TelemetryError(f"line {line_number}: event_id must be a non-negative integer")
    details = record.get("details")
    if not isinstance(details, dict):
        raise TelemetryError(f"line {line_number}: details must be a JSON object")
    return Event(
        timestamp=timestamp,
        event_id=event_id,
        host=_required_text(record, "host"),
        user=_required_text(record, "user"),
        event_type=_required_text(record, "event_type").lower(),
        details=details,
    )


def load_events(path: Path) -> tuple[Event, ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise TelemetryError(f"could not read {path}: {exc}") from exc
    events: list[Event] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TelemetryError(f"line {line_number}: invalid JSON") from exc
        events.append(parse_event(record, line_number))
    return tuple(sorted(events, key=lambda event: (event.timestamp, event.host, event.event_id)))


def _detail(event: Event, key: str) -> str:
    value = event.details.get(key, "")
    return value if isinstance(value, str) else str(value)


def _process_name(event: Event) -> str:
    return PureWindowsPath(_detail(event, "process_name")).name.lower()


def _detection(
    event: Event,
    rule_id: str,
    title: str,
    severity: str,
    tactic: str,
    technique_id: str,
    summary: str,
    evidence: str,
) -> Detection:
    return Detection(rule_id, title, severity, tactic, technique_id, event.host, event.timestamp, summary, evidence)


def detect_encoded_powershell(event: Event) -> Detection | None:
    if event.event_type != "process_create" or _process_name(event) not in {"powershell.exe", "pwsh.exe"}:
        return None
    command = _detail(event, "command_line")
    if re.search(r"(?i)(?:^|\s)-(?:enc|encodedcommand)(?:\s|$)", command) is None:
        return None
    return _detection(event, "RANSOM-001", "Encoded PowerShell execution", "high", "Execution", "T1059.001", "A PowerShell process used an encoded-command option.", f"process={_process_name(event)}; option=encoded-command")


def detect_lsass_access(event: Event) -> Detection | None:
    if event.event_type != "process_access":
        return None
    target = PureWindowsPath(_detail(event, "target_image")).name.lower()
    access = _detail(event, "granted_access").lower()
    if target != "lsass.exe" or access not in SUSPICIOUS_LSASS_ACCESS:
        return None
    return _detection(event, "RANSOM-002", "Suspicious LSASS process access", "critical", "Credential Access", "T1003.001", "A process requested an access mask commonly associated with LSASS memory access.", f"source={_process_name(event)}; target=lsass.exe; access={access}")


def detect_remote_service(event: Event) -> Detection | None:
    if event.event_type != "service_install":
        return None
    service_name = _detail(event, "service_name").lower()
    image_path = _detail(event, "service_image_path").lower()
    if "psexesvc" not in service_name and "admin$" not in image_path and "\\\\" not in image_path:
        return None
    return _detection(event, "RANSOM-003", "Remote service lateral movement", "high", "Lateral Movement", "T1021.002", "A remotely staged service indicates SMB/admin-share lateral movement.", f"service={service_name or 'unknown'}; remote-path-observed=true")


def detect_recovery_inhibition(event: Event) -> Detection | None:
    if event.event_type != "process_create":
        return None
    process = _process_name(event)
    command = _detail(event, "command_line").lower()
    matched = (
        process == "vssadmin.exe" and "delete" in command and "shadows" in command
    ) or (
        process == "wbadmin.exe" and "delete" in command and "catalog" in command
    ) or (
        process == "bcdedit.exe" and "recoveryenabled" in command and " no" in command
    )
    if not matched:
        return None
    return _detection(event, "RANSOM-004", "System recovery inhibited", "critical", "Impact", "T1490", "A system utility was used to impair recovery options.", f"process={process}; recovery-modification=true")


def detect_log_clear(event: Event) -> Detection | None:
    if event.event_type != "log_cleared" and event.event_id != 1102:
        return None
    return _detection(event, "RANSOM-005", "Windows audit log cleared", "high", "Defense Evasion", "T1070.001", "Windows audit telemetry indicates a cleared event log.", f"event_id={event.event_id}; channel={_detail(event, 'channel') or 'Security'}")


def detect_ransom_note(event: Event) -> Detection | None:
    if event.event_type not in {"file_create", "file_write"}:
        return None
    name = PureWindowsPath(_detail(event, "target_path")).name.lower()
    if name not in RANSOM_NOTE_NAMES:
        return None
    return _detection(event, "RANSOM-007", "Ransom-note artifact created", "critical", "Impact", "T1486", "A filename matching a known ransom-note pattern was created.", f"file={name}")


EVENT_RULES = (
    detect_encoded_powershell,
    detect_lsass_access,
    detect_remote_service,
    detect_recovery_inhibition,
    detect_log_clear,
    detect_ransom_note,
)


def detect_file_bursts(events: Sequence[Event], threshold: int = 5, window_seconds: int = 60) -> tuple[Detection, ...]:
    by_host: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        suffix = PureWindowsPath(_detail(event, "target_path")).suffix.lower()
        if event.event_type == "file_write" and suffix in ENCRYPTED_EXTENSIONS:
            by_host[event.host].append(event)
    detections: list[Detection] = []
    window = timedelta(seconds=window_seconds)
    for host, writes in by_host.items():
        start = 0
        for end, event in enumerate(writes):
            while event.timestamp - writes[start].timestamp > window:
                start += 1
            current = writes[start : end + 1]
            unique_paths = {_detail(item, "target_path").lower() for item in current}
            if len(unique_paths) >= threshold:
                detections.append(
                    _detection(event, "RANSOM-006", "Rapid encrypted-file modification burst", "critical", "Impact", "T1486", f"At least {threshold} files gained encryption-associated extensions within {window_seconds} seconds.", f"unique_files={len(unique_paths)}; window_seconds={window_seconds}")
                )
                break
    return tuple(detections)


def analyze(events: Sequence[Event]) -> Incident:
    findings: list[Detection] = []
    for event in events:
        for rule in EVENT_RULES:
            finding = rule(event)
            if finding is not None:
                findings.append(finding)
    findings.extend(detect_file_bursts(events))
    ordered = tuple(sorted(findings, key=lambda finding: (finding.timestamp, SEVERITY_ORDER[finding.severity], finding.rule_id)))
    techniques = tuple(sorted({finding.technique_id for finding in ordered}))
    hosts = tuple(sorted({finding.host for finding in ordered}))
    rules = {finding.rule_id for finding in ordered}
    correlated_chain = _has_correlated_attack_chain(ordered)
    if correlated_chain == "critical":
        severity = "critical"
    elif correlated_chain == "high":
        severity = "high"
    elif findings:
        severity = "medium"
    else:
        severity = "informational"
    confidence = "high" if len(rules) >= 5 else "medium" if len(rules) >= 2 else "low"
    return Incident(severity, confidence, ordered, hosts, techniques)


def _has_correlated_attack_chain(findings: Sequence[Detection]) -> str | None:
    """Return severity for a multi-technique chain on one host within 15 minutes."""
    by_host: dict[str, list[Detection]] = defaultdict(list)
    for finding in findings:
        by_host[finding.host].append(finding)

    window = timedelta(seconds=ATTACK_CHAIN_WINDOW_SECONDS)
    chain_severity: str | None = None
    for host_findings in by_host.values():
        host_findings.sort(key=lambda finding: finding.timestamp)
        start = 0
        for end, finding in enumerate(host_findings):
            while finding.timestamp - host_findings[start].timestamp > window:
                start += 1
            current = host_findings[start : end + 1]
            techniques = {item.technique_id for item in current}
            if "T1486" in techniques and len(techniques) >= 4 and any(item.rule_id == "RANSOM-006" for item in current):
                return "critical"
            if len(techniques) >= 3:
                chain_severity = "high"
    return chain_severity


def _same_file_path(first: Path, second: Path) -> bool:
    if first.resolve() == second.resolve():
        return True
    try:
        return first.samefile(second)
    except OSError:
        return False


def _write_atomic(path: Path, content: str) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def recommended_actions(incident: Incident) -> tuple[str, ...]:
    techniques = set(incident.techniques)
    actions: list[str] = []
    if incident.severity in {"critical", "high"}:
        actions.append("Isolate affected hosts through approved EDR or network controls while preserving volatile evidence.")
    if "T1003.001" in techniques:
        actions.append("Disable or reset potentially exposed accounts and review privileged authentication from the affected hosts.")
    if "T1021.002" in techniques:
        actions.append("Restrict SMB/admin-share lateral movement and hunt for the same service artifact across peer systems.")
    if "T1490" in techniques:
        actions.append("Protect offline backups and validate recovery media before beginning restoration.")
    if "T1486" in techniques:
        actions.append("Preserve encrypted samples and ransom notes; restore only after eradication and clean-host validation.")
    actions.append("Retain the synthetic timeline, detection evidence, and analyst decisions for lessons learned.")
    return tuple(actions)


def _cell(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_report(incident: Incident, source_name: str) -> str:
    lines = [
        "# Ransomware Incident Analysis",
        "",
        "> Educational analysis of sanitized, synthetic telemetry. No malware or destructive command was executed.",
        "",
        f"Source: `{source_name}`",
        "",
        f"Incident severity: **{incident.severity.upper()}**",
        f"Analytic confidence: **{incident.confidence.upper()}**",
        f"Detections: **{len(incident.findings)}**",
        f"Affected hosts: **{', '.join(incident.affected_hosts) if incident.affected_hosts else 'None'}**",
        "",
        "## Executive assessment",
        "",
    ]
    if incident.severity == "critical":
        lines.append("The correlated evidence is consistent with a multi-stage ransomware incident that reached data-impact activity. Immediate containment and credential-risk review are warranted in the modeled scenario.")
    elif incident.findings:
        lines.append("Suspicious activity was detected, but the evidence did not meet the lab's critical ransomware-correlation threshold.")
    else:
        lines.append("No ransomware detection rule fired and no incident response escalation is recommended for this dataset.")
    lines.extend(["", "## Detection timeline", "", "| Time (UTC) | Host | Rule | Severity | ATT&CK | Evidence |", "| --- | --- | --- | --- | --- | --- |"])
    if not incident.findings:
        lines.append("| — | — | — | — | — | No detections |")
    for finding in incident.findings:
        row = (
            finding.timestamp.isoformat(),
            finding.host,
            f"{finding.rule_id}: {finding.title}",
            finding.severity.title(),
            finding.technique_id,
            finding.evidence,
        )
        lines.append("| " + " | ".join(_cell(value) for value in row) + " |")
    lines.extend(["", "## MITRE ATT&CK coverage", ""])
    if incident.techniques:
        lines.extend(f"- `{technique}`" for technique in incident.techniques)
    else:
        lines.append("- No techniques detected")
    lines.extend(["", "## Recommended response", ""])
    lines.extend(f"{index}. {action}" for index, action in enumerate(recommended_actions(incident), start=1))
    lines.extend(
        [
            "",
            "## Recovery validation checklist",
            "",
            "- Confirm the initial access path is closed.",
            "- Confirm persistence and remote-service artifacts are removed.",
            "- Validate privileged credentials were rotated where exposure was plausible.",
            "- Restore from known-good backups to isolated systems first.",
            "- Monitor restored systems for recurrence before returning them to production networks.",
            "",
        ]
    )
    return "\n".join(lines)


def render_json(incident: Incident) -> str:
    payload = asdict(incident)
    for finding in payload["findings"]:
        finding["timestamp"] = finding["timestamp"].isoformat()
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="sanitized JSONL telemetry")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--fail-on-incident", action="store_true", help="return 1 for high or critical incidents")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        incident = analyze(load_events(args.input))
    except TelemetryError as exc:
        print(f"Error: {exc}")
        return 2
    content = render_json(incident) if args.format == "json" else render_report(incident, args.input.name)
    if args.output:
        if _same_file_path(args.input, args.output):
            print("Error: --output must not refer to the input telemetry file")
            return 2
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            _write_atomic(args.output, content)
        except OSError as exc:
            print(f"Error: could not write {args.output}: {exc}")
            return 2
    else:
        print(content)
    return 1 if args.fail_on_incident and incident.severity in {"high", "critical"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
