import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class VulnerabilityFinding:
    package: str
    installed_version: str
    vulnerability_id: str
    fix_versions: tuple[str, ...]
    aliases: tuple[str, ...]
    description: str


class DependencyScanError(Exception):
    """Raised when a dependency scan cannot be completed."""


def scan_dependencies(
    requirements_file: str | Path,
) -> list[VulnerabilityFinding]:
    """Scan a requirements file and return discovered vulnerabilities."""
    requirements_path = Path(requirements_file)

    if not requirements_path.is_file():
        raise DependencyScanError(
            f"Requirements file not found: {requirements_path}"
        )

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip_audit",
                "--format",
                "json",
                "-r",
                str(requirements_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DependencyScanError(
            "Dependency scan timed out after 120 seconds."
        ) from exc
    except OSError as exc:
        raise DependencyScanError(
            f"Could not start pip-audit: {exc}"
        ) from exc

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        detail = result.stderr.strip() or "No valid JSON output received."
        raise DependencyScanError(
            f"Could not parse pip-audit output: {detail}"
        ) from exc

    if result.returncode not in (0, 1):
        detail = result.stderr.strip() or "Unknown scanner error."
        raise DependencyScanError(
            f"pip-audit exited with code {result.returncode}: {detail}"
        )

    # pip-audit's JSON output is normally a list of dependencies.
    # Accept a wrapped "dependencies" object as well.
    if isinstance(data, dict):
        data = data.get("dependencies")

    if not isinstance(data, list):
        raise DependencyScanError(
            "Unexpected pip-audit JSON structure."
        )

    findings: list[VulnerabilityFinding] = []

    for dependency in data:
        if not isinstance(dependency, dict):
            raise DependencyScanError(
                "Unexpected dependency entry in pip-audit output."
            )

        package = dependency.get("name", "unknown")
        version = dependency.get("version", "unknown")
        vulnerabilities = dependency.get("vulns", [])

        if not isinstance(vulnerabilities, list):
            raise DependencyScanError(
                f"Invalid vulnerability data for package {package}."
            )

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise DependencyScanError(
                    f"Invalid vulnerability entry for package {package}."
                )
            
            fix_versions = vulnerability.get("fix_versions") or []
            aliases = vulnerability.get("aliases") or []

            if not isinstance(fix_versions, list) or not all(
                isinstance(item, str) for item in fix_versions
            ):
                raise DependencyScanError(
                    f"Invalid fix_versions data for package {package}."
                )

            if not isinstance(aliases, list) or not all(
                isinstance(item, str) for item in aliases
            ):
                raise DependencyScanError(
                    f"Invalid aliases data for package {package}."
                )

            findings.append(
                VulnerabilityFinding(
                    package=package,
                    installed_version=version,
                    vulnerability_id=vulnerability.get("id", "unknown"),
                    fix_versions=tuple(fix_versions),
                    aliases=tuple(aliases),
                    description=vulnerability.get("description") or "",
                )
            )

            



    return findings