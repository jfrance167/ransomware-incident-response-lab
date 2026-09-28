import io
import json
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ransomware_ir import (
    Detection,
    Event,
    TelemetryError,
    analyze,
    detect_encoded_powershell,
    detect_file_bursts,
    detect_lsass_access,
    detect_log_clear,
    detect_recovery_inhibition,
    detect_remote_service,
    load_events,
    main,
    parse_event,
    recommended_actions,
    render_report,
)


ROOT = Path(__file__).resolve().parents[1]
ATTACK = ROOT / "samples" / "ransomware-attack.jsonl"
BENIGN = ROOT / "samples" / "benign-control.jsonl"


def event(event_type="process_create", **details):
    return Event(datetime(2026, 1, 1, tzinfo=timezone.utc), 1, "HOST-1", "LAB\\user", event_type, details)


class RansomwareIRTests(unittest.TestCase):
    def test_attack_dataset_is_critical(self):
        incident = analyze(load_events(ATTACK))
        self.assertEqual(incident.severity, "critical")
        self.assertEqual(incident.confidence, "high")
        self.assertEqual(len(incident.findings), 7)

    def test_attack_dataset_maps_expected_techniques(self):
        techniques = set(analyze(load_events(ATTACK)).techniques)
        self.assertEqual(techniques, {"T1003.001", "T1021.002", "T1059.001", "T1070.001", "T1486", "T1490"})

    def test_findings_on_different_hosts_do_not_form_high_severity_chain(self):
        timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            Event(timestamp, 1, "HOST-1", "U", "process_create", {"process_name": "powershell.exe", "command_line": "powershell -EncodedCommand SAFE"}),
            Event(timestamp, 2, "HOST-2", "U", "process_access", {"process_name": "agent.exe", "target_image": "lsass.exe", "granted_access": "0x1010"}),
            Event(timestamp, 3, "HOST-3", "U", "process_create", {"process_name": "vssadmin.exe", "command_line": "vssadmin delete shadows /all"}),
            Event(timestamp, 4, "HOST-4", "U", "log_cleared", {}),
        ]
        events.extend(
            Event(timestamp + timedelta(seconds=index), 11, "HOST-5", "U", "file_write", {"target_path": f"C:\\Data\\file{index}.locked"})
            for index in range(5)
        )

        incident = analyze(events)

        self.assertEqual(incident.severity, "medium")
        self.assertEqual(len(incident.affected_hosts), 5)

    def test_findings_outside_chain_window_do_not_form_high_severity_chain(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            Event(start, 1, "HOST-1", "U", "process_create", {"process_name": "powershell.exe", "command_line": "powershell -EncodedCommand SAFE"}),
            Event(start + timedelta(minutes=20), 2, "HOST-1", "U", "process_access", {"process_name": "agent.exe", "target_image": "lsass.exe", "granted_access": "0x1010"}),
            Event(start + timedelta(minutes=40), 3, "HOST-1", "U", "process_create", {"process_name": "vssadmin.exe", "command_line": "vssadmin delete shadows /all"}),
            Event(start + timedelta(minutes=60), 4, "HOST-1", "U", "log_cleared", {}),
        ]
        events.extend(
            Event(start + timedelta(minutes=80, seconds=index), 11, "HOST-1", "U", "file_write", {"target_path": f"C:\\Data\\file{index}.locked"})
            for index in range(5)
        )

        incident = analyze(events)

        self.assertEqual(incident.severity, "medium")

    def test_benign_control_has_no_findings(self):
        incident = analyze(load_events(BENIGN))
        self.assertEqual(incident.severity, "informational")
        self.assertEqual(incident.findings, ())

    def test_encoded_powershell_detection(self):
        finding = detect_encoded_powershell(event(process_name="powershell.exe", command_line="powershell -enc SAFE_PLACEHOLDER"))
        self.assertIsNotNone(finding)

    def test_plain_powershell_is_not_flagged(self):
        self.assertIsNone(detect_encoded_powershell(event(process_name="powershell.exe", command_line="powershell -File inventory.ps1")))

    def test_lsass_access_requires_suspicious_mask(self):
        suspicious = event("process_access", process_name="agent.exe", target_image="lsass.exe", granted_access="0x1010")
        benign = event("process_access", process_name="monitor.exe", target_image="lsass.exe", granted_access="0x1000")
        self.assertIsNotNone(detect_lsass_access(suspicious))
        self.assertIsNone(detect_lsass_access(benign))

    def test_remote_service_detection(self):
        finding = detect_remote_service(event("service_install", service_name="PSEXESVC", service_image_path=r"\\HOST\ADMIN$\svc.exe"))
        self.assertIsNotNone(finding)

    def test_ordinary_local_service_is_not_flagged(self):
        finding = detect_remote_service(event("service_install", service_name="Updater", service_image_path=r"C:\Program Files\Updater\svc.exe"))
        self.assertIsNone(finding)

    def test_recovery_inhibition_detection(self):
        finding = detect_recovery_inhibition(event(process_name="vssadmin.exe", command_line="vssadmin delete shadows /all"))
        self.assertIsNotNone(finding)

    def test_shadow_listing_is_not_flagged(self):
        finding = detect_recovery_inhibition(event(process_name="vssadmin.exe", command_line="vssadmin list shadows"))
        self.assertIsNone(finding)

    def test_log_clear_detection_accepts_event_id(self):
        sample = Event(datetime(2026, 1, 1, tzinfo=timezone.utc), 1102, "HOST-1", "LAB\\user", "windows_event", {})
        self.assertIsNotNone(detect_log_clear(sample))

    def test_file_burst_threshold(self):
        events = tuple(
            Event(datetime(2026, 1, 1, 0, 0, index, tzinfo=timezone.utc), 11, "HOST-1", "SYSTEM", "file_write", {"target_path": f"C:\\Data\\file{index}.locked"})
            for index in range(5)
        )
        self.assertEqual(len(detect_file_bursts(events)), 1)

    def test_file_burst_below_threshold_is_quiet(self):
        events = tuple(
            Event(datetime(2026, 1, 1, 0, 0, index, tzinfo=timezone.utc), 11, "HOST-1", "SYSTEM", "file_write", {"target_path": f"C:\\Data\\file{index}.locked"})
            for index in range(4)
        )
        self.assertEqual(detect_file_bursts(events), ())

    def test_duplicate_file_paths_do_not_meet_threshold(self):
        events = tuple(
            Event(datetime(2026, 1, 1, 0, 0, index, tzinfo=timezone.utc), 11, "HOST-1", "SYSTEM", "file_write", {"target_path": "C:\\Data\\same.locked"})
            for index in range(5)
        )
        self.assertEqual(detect_file_bursts(events), ())

    def test_parse_rejects_timestamp_without_timezone(self):
        record = {"timestamp": "2026-01-01T00:00:00", "event_id": 1, "host": "H", "user": "U", "event_type": "x", "details": {}}
        with self.assertRaises(TelemetryError):
            parse_event(record, 1)

    def test_load_rejects_invalid_json(self):
        path = Path(__file__).parent / "_invalid.jsonl"
        path.write_text("{invalid", encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        with self.assertRaises(TelemetryError):
            load_events(path)

    def test_events_are_sorted_chronologically(self):
        path = Path(__file__).parent / "_unordered.jsonl"
        first = {"timestamp": "2026-01-01T00:00:00Z", "event_id": 1, "host": "H", "user": "U", "event_type": "x", "details": {}}
        second = dict(first, timestamp="2026-01-01T00:01:00Z")
        path.write_text(json.dumps(second) + "\n" + json.dumps(first), encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        loaded = load_events(path)
        self.assertLess(loaded[0].timestamp, loaded[1].timestamp)

    def test_report_escapes_untrusted_cells(self):
        finding = Detection("TEST", "Title", "high", "Impact", "T0000", "bad|host\nnext", datetime(2026, 1, 1, tzinfo=timezone.utc), "summary", "evidence")
        incident = analyze(())
        incident = incident.__class__("high", "low", (finding,), (finding.host,), (finding.technique_id,))
        report = render_report(incident, "fixture.jsonl")
        self.assertIn("bad\\|host next", report)

    def test_response_includes_credential_action(self):
        incident = analyze(load_events(ATTACK))
        self.assertTrue(any("accounts" in action for action in recommended_actions(incident)))

    def test_cli_control_succeeds_with_fail_gate(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(BENIGN), "--fail-on-incident"]), 0)

    def test_cli_attack_fails_with_fail_gate(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(ATTACK), "--fail-on-incident"]), 1)

    def test_cli_rejects_output_that_is_input_file(self):
        telemetry = ROOT / "tests" / "_cli_collision_input.jsonl"
        self.addCleanup(telemetry.unlink, missing_ok=True)
        telemetry.write_text(BENIGN.read_text(encoding="utf-8"), encoding="utf-8")
        original = telemetry.read_bytes()
        output = io.StringIO()
        with redirect_stdout(output):
            result = main([str(telemetry), "--output", str(telemetry)])

        self.assertEqual(result, 2)
        self.assertIn("must not refer to the input", output.getvalue())
        self.assertEqual(telemetry.read_bytes(), original)

    def test_cli_writes_report_to_separate_output_file(self):
        telemetry = ROOT / "tests" / "_cli_output_input.jsonl"
        output_dir = ROOT / "tests" / "_cli_output_dir"
        report = output_dir / "report.json"
        self.addCleanup(output_dir.rmdir)
        self.addCleanup(report.unlink, missing_ok=True)
        self.addCleanup(telemetry.unlink, missing_ok=True)
        telemetry.write_text(BENIGN.read_text(encoding="utf-8"), encoding="utf-8")
        original = telemetry.read_bytes()

        result = main([str(telemetry), "--format", "json", "--output", str(report)])

        self.assertEqual(result, 0)
        self.assertEqual(json.loads(report.read_text(encoding="utf-8"))["severity"], "informational")
        self.assertEqual(telemetry.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
