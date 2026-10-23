
import json

from guardrail.reporting import write_json_report


def test_writes_block_report(tmp_path):
    report_path = tmp_path / "reports" / "scan.json"

    findings = [
        {
            "rule_id": "GR002",
            "severity": "MEDIUM",
            "message": "Image uses the mutable latest tag.",
            "line_number": 1,
        }
    ]

    write_json_report(
        report_path,
        status="BLOCK",
        findings=findings,
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["tool"] == "GuardRail"
    assert report["status"] == "BLOCK"
    assert report["finding_count"] == 1
    assert report["findings"][0]["rule_id"] == "GR002"


def test_writes_pass_report_with_no_findings(tmp_path):
    report_path = tmp_path / "scan.json"

    write_json_report(
        report_path,
        status="PASS",
        findings=[],
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["status"] == "PASS"
    assert report["finding_count"] == 0
    assert report["findings"] == []


def test_creates_missing_report_directory(tmp_path):
    report_path = tmp_path / "new" / "nested" / "scan.json"

    write_json_report(
        report_path,
        status="ERROR",
        findings=[],
    )

    assert report_path.is_file()
