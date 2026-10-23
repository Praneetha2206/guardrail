import json

import pytest

from guardrail.cli import main


def test_cli_main_runs_without_error(monkeypatch):
    monkeypatch.setattr("sys.argv", ["guardrail"])
    main()


def test_cli_version(monkeypatch):
    monkeypatch.setattr("sys.argv", ["guardrail", "--version"])

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 0


def test_scan_passes_when_dockerfile_has_no_findings(
    monkeypatch, tmp_path
):
    from guardrail.cli import main

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        "USER 10001\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        ["guardrail", "scan", "--dockerfile", str(dockerfile)],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 0


def test_scan_blocks_when_dockerfile_has_findings(
    monkeypatch, tmp_path
):
    from guardrail.cli import main

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:latest\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        ["guardrail", "scan", "--dockerfile", str(dockerfile)],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1


def test_scan_returns_error_when_dockerfile_is_missing(
    monkeypatch, tmp_path
):
    from guardrail.cli import main

    missing_dockerfile = tmp_path / "missing-Dockerfile"

    monkeypatch.setattr(
        "sys.argv",
        [
            "guardrail",
            "scan",
            "--dockerfile",
            str(missing_dockerfile),
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 2

def test_scan_writes_pass_status_to_json_report(
    monkeypatch, tmp_path
):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        "USER 10001\n",
        encoding="utf-8",
    )
    report = tmp_path / "report.json"

    monkeypatch.setattr(
        "sys.argv",
        [
            "guardrail",
            "scan",
            "--dockerfile",
            str(dockerfile),
            "--json-report",
            str(report),
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 0

    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["status"] == "PASS"
    assert data["findings"] == []


def test_scan_writes_block_findings_to_json_report(
    monkeypatch, tmp_path
):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:latest\n",
        encoding="utf-8",
    )
    report = tmp_path / "report.json"

    monkeypatch.setattr(
        "sys.argv",
        [
            "guardrail",
            "scan",
            "--dockerfile",
            str(dockerfile),
            "--json-report",
            str(report),
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1

    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["status"] == "BLOCK"
    assert len(data["findings"]) > 0
    assert data["findings"][0]["type"] == "dockerfile"


def test_scan_returns_error_when_dependency_scan_fails(
    monkeypatch, tmp_path
):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "example-package==1.0.0\n",
        encoding="utf-8",
    )

    def fake_scan_dependencies(requirements_file):
        from guardrail.dependency_scanner import DependencyScanError

        raise DependencyScanError("Simulated scanner failure")

    monkeypatch.setattr(
        "guardrail.cli.scan_dependencies",
        fake_scan_dependencies,
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "guardrail",
            "scan",
            "--requirements",
            str(requirements),
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 2
