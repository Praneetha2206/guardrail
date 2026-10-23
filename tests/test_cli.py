
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
