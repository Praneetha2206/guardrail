
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
