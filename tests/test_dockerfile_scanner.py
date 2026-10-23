from guardrail.dockerfile_scanner import scan_dockerfile


def test_reports_missing_user_instruction(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        "RUN pip install flask\n",
        encoding="utf-8",
    )

    findings = scan_dockerfile(dockerfile)

    assert len(findings) == 1
    assert findings[0].rule_id == "GR001"
    assert findings[0].severity == "HIGH"


def test_accepts_user_instruction(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        "RUN pip install flask\n"
        "USER 10001\n",
        encoding="utf-8",
    )

    findings = scan_dockerfile(dockerfile)

    assert findings == []

def test_reports_latest_image_tag(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:latest\n"
        "USER 10001\n",
        encoding="utf-8",
    )

    findings = scan_dockerfile(dockerfile)

    assert len(findings) == 1
    assert findings[0].rule_id == "GR002"
    assert findings[0].line_number == 1


def test_accepts_pinned_image_tag(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        "USER 10001\n",
        encoding="utf-8",
    )

    findings = scan_dockerfile(dockerfile)

    assert findings == []

def test_reports_remote_script_piped_to_shell(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        "RUN curl -fsSL https://example.com/install.sh | sh\n"
        "USER 10001\n",
        encoding="utf-8",
    )

    findings = scan_dockerfile(dockerfile)

    assert len(findings) == 1
    assert findings[0].rule_id == "GR003"
    assert findings[0].line_number == 2
    assert findings[0].severity == "HIGH"


def test_accepts_run_without_remote_script_pipe(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        "RUN pip install flask\n"
        "USER 10001\n",
        encoding="utf-8",
    )

    findings = scan_dockerfile(dockerfile)

    assert findings == []


def test_reports_root_user_by_name(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        "USER root\n",
        encoding="utf-8",
    )

    findings = scan_dockerfile(dockerfile)

    assert len(findings) == 1
    assert findings[0].rule_id == "GR001"
    assert findings[0].line_number == 2
    assert findings[0].severity == "HIGH"


def test_reports_root_user_by_uid(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        "USER 0:0\n",
        encoding="utf-8",
    )

    findings = scan_dockerfile(dockerfile)

    assert len(findings) == 1
    assert findings[0].rule_id == "GR001"
    assert findings[0].line_number == 2


def test_accepts_non_root_user_by_name(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        "USER app\n",
        encoding="utf-8",
    )

    findings = scan_dockerfile(dockerfile)

    assert findings == []



def test_reports_user_switching_back_to_root(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim\n"
        "USER app\n"
        "USER root\n",
        encoding="utf-8",
    )

    findings = scan_dockerfile(dockerfile)

    root_findings = [
        finding
        for finding in findings
        if finding.rule_id == "GR001"
    ]

    assert len(root_findings) == 1
    assert root_findings[0].line_number == 3


def test_reports_build_stage_without_user_instruction(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.13-slim AS builder\n"
        "USER app\n"
        "RUN echo build\n"
        "FROM python:3.13-slim AS runtime\n"
        "CMD [\"python\", \"--version\"]\n",
        encoding="utf-8",
    )

    findings = scan_dockerfile(dockerfile)

    assert any(
        finding.rule_id == "GR001"
        and finding.line_number == 4
        for finding in findings
    )
