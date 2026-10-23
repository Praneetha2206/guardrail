import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DockerfileFinding:
    rule_id: str
    message: str
    line_number: int
    severity: str


def scan_dockerfile(
    dockerfile_path: str | Path,
) -> list[DockerfileFinding]:
    """Check a Dockerfile for basic security-policy violations."""
    path = Path(dockerfile_path)

    if not path.is_file():
        raise FileNotFoundError(f"Dockerfile not found: {path}")

    findings: list[DockerfileFinding] = []

    lines = path.read_text(encoding="utf-8").splitlines()

    has_user_instruction = any(
        line.strip().upper().startswith("USER ")
        for line in lines
    )

    if not has_user_instruction:
        findings.append(
            DockerfileFinding(
                rule_id="GR001",
                message="Dockerfile does not specify a USER instruction.",
                line_number=1,
                severity="HIGH",
            )
        )
    for line_number, line in enumerate(lines, start=1):
        stripped_line = line.strip()

        if stripped_line.upper().startswith("FROM "):
            image_reference = stripped_line.split()[1]

            if image_reference.endswith(":latest"):
                findings.append(
                    DockerfileFinding(
                        rule_id="GR002",
                        message=(
                            f"Image uses the mutable 'latest' tag: "
                            f"{image_reference}."
                        ),
                        line_number=line_number,
                        severity="MEDIUM",
                    )
                )
        remote_script_pattern = re.compile(
        r"\b(curl|wget)\b.*\|\s*(sh|bash)\b",
        re.IGNORECASE,
    )

    for line_number, line in enumerate(lines, start=1):
        stripped_line = line.strip()

        if (
            stripped_line.upper().startswith("RUN ")
            and remote_script_pattern.search(stripped_line)
        ):
            findings.append(
                    DockerfileFinding(
                        rule_id="GR003",
                        message=(
                            "RUN instruction pipes a remote download "
                            "directly into a shell."
                        ),
                        line_number=line_number,
                        severity="HIGH",
                    )
                )
    return findings