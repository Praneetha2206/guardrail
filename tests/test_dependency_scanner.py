import json
import subprocess

import pytest

from guardrail.dependency_scanner import (
    DependencyScanError,
    scan_dependencies,
)


def test_scan_returns_vulnerability_findings(tmp_path, monkeypatch):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("example-package==1.0.0\n", encoding="utf-8")

    audit_output = [
        {
            "name": "example-package",
            "version": "1.0.0",
            "vulns": [
                {
                    "id": "PYSEC-TEST-001",
                    "fix_versions": ["1.0.1"],
                    "aliases": ["CVE-2099-0001"],
                    "description": "A simulated vulnerability.",
                }
            ],
        }
    ]

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout=json.dumps(audit_output),
            stderr="",
        )

    monkeypatch.setattr(
        "guardrail.dependency_scanner.subprocess.run",
        fake_run,
    )

    findings = scan_dependencies(requirements)

    assert len(findings) == 1
    assert findings[0].package == "example-package"
    assert findings[0].installed_version == "1.0.0"
    assert findings[0].vulnerability_id == "PYSEC-TEST-001"
    assert findings[0].fix_versions == ("1.0.1",)


def test_scan_returns_empty_list_when_no_vulnerabilities(
    tmp_path, monkeypatch
):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("example-package==1.0.0\n", encoding="utf-8")

    audit_output = [
        {
            "name": "example-package",
            "version": "1.0.0",
            "vulns": [],
        }
    ]

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=json.dumps(audit_output),
            stderr="",
        )

    monkeypatch.setattr(
        "guardrail.dependency_scanner.subprocess.run",
        fake_run,
    )

    assert scan_dependencies(requirements) == []


def test_scan_rejects_missing_requirements_file(tmp_path):
    missing_file = tmp_path / "missing.txt"

    with pytest.raises(DependencyScanError, match="not found"):
        scan_dependencies(missing_file)


def test_scan_rejects_invalid_json(tmp_path, monkeypatch):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("example-package==1.0.0\n", encoding="utf-8")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=2,
            stdout="not valid JSON",
            stderr="Scanner failed",
        )

    monkeypatch.setattr(
        "guardrail.dependency_scanner.subprocess.run",
        fake_run,
    )

    with pytest.raises(DependencyScanError, match="parse"):
        scan_dependencies(requirements)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("fix_versions", "1.0.1"),
        ("aliases", "CVE-2099-0001"),
    ],
)
def test_scan_rejects_invalid_vulnerability_metadata(
    tmp_path, monkeypatch, field, invalid_value
):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("example-package==1.0.0\n", encoding="utf-8")

    audit_output = [
        {
            "name": "example-package",
            "version": "1.0.0",
            "vulns": [
                {
                    "id": "PYSEC-TEST-001",
                    "fix_versions": ["1.0.1"],
                    "aliases": ["CVE-2099-0001"],
                    "description": "A simulated vulnerability.",
                }
            ],
        }
    ]
    audit_output[0]["vulns"][0][field] = invalid_value

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout=json.dumps(audit_output),
            stderr="",
        )

    monkeypatch.setattr(
        "guardrail.dependency_scanner.subprocess.run",
        fake_run,
    )

    with pytest.raises(DependencyScanError, match=field):
        scan_dependencies(requirements)



def test_scan_handles_timeout(tmp_path, monkeypatch):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("example-package==1.0.0\n", encoding="utf-8")

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=120)

    monkeypatch.setattr(
        "guardrail.dependency_scanner.subprocess.run",
        fake_run,
    )

    with pytest.raises(DependencyScanError, match="timed out"):
        scan_dependencies(requirements)


def test_scan_handles_launch_failure(tmp_path, monkeypatch):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("example-package==1.0.0\n", encoding="utf-8")

    def fake_run(*args, **kwargs):
        raise OSError("Simulated process launch failure")

    monkeypatch.setattr(
        "guardrail.dependency_scanner.subprocess.run",
        fake_run,
    )

    with pytest.raises(DependencyScanError, match="Could not start pip-audit"):
        scan_dependencies(requirements)


def test_scan_rejects_unexpected_exit_code(tmp_path, monkeypatch):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("example-package==1.0.0\n", encoding="utf-8")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=2,
            stdout="[]",
            stderr="Unexpected scanner failure",
        )

    monkeypatch.setattr(
        "guardrail.dependency_scanner.subprocess.run",
        fake_run,
    )

    with pytest.raises(
        DependencyScanError,
        match="exited with code 2",
    ):
        scan_dependencies(requirements)
