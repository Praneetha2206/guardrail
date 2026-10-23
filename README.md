# GuardRail

GuardRail is a policy-driven DevSecOps security gate built in Python. It scans Python dependencies for known vulnerabilities and checks Dockerfiles for selected security misconfigurations.

The goal is to identify security issues early and provide clear, machine-readable results that can be used in development and CI workflows.

## Features

- **Dependency vulnerability scanning:** Integrates with `pip-audit` to identify known vulnerabilities in dependencies listed in a requirements file.
- **Dockerfile security checks:** Detects selected insecure configuration patterns.
- **Security findings:** Reports rule identifiers, severity, messages, and relevant line numbers where available.
- **JSON reports:** Exports scan results for further processing.
- **Exit codes:** Supports automated decisions based on scan outcomes.
- **Automated quality checks:** Uses pytest, Ruff, and GitHub Actions.

## Security rules

| Rule | Severity | Description |
|---|---|---|
| GR001 | HIGH | Detects build stages without a `USER` instruction and explicit root-user configuration. |
| GR002 | MEDIUM | Detects image references using the mutable `latest` tag. |
| GR003 | HIGH | Detects `RUN` commands that pipe `curl` or `wget` output into `sh` or `bash`. |

These are static checks for selected patterns, not a complete Dockerfile security analysis.

Dependency findings are provided by `pip-audit` and the vulnerability data it uses.

## Requirements

- Python 3.13 or later
- pip
- Internet access for dependency vulnerability database lookups

## Installation

Clone the repository and enter its directory:

```bash
git clone https://github.com/Praneetha2206/guardrail.git
cd guardrail
```

Create and activate a virtual environment.

Windows PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux or macOS:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
```

Install GuardRail and its development tools:

```bash
python -m pip install -e ".[dev]"
```

Verify the installation:

```bash
guardrail --version
guardrail --help
```

## Usage

### Scan a Dockerfile

```bash
guardrail scan --dockerfile tests/fixtures/clean/Dockerfile
```

Scan a Dockerfile containing known test violations:

```bash
guardrail scan --dockerfile tests/fixtures/misconfigured/Dockerfile
```

### Scan Python dependencies

Scan a requirements file:

```bash
guardrail scan --requirements requirements.txt
```

The requirements file must exist. GuardRail invokes `pip-audit` to check the listed dependencies.

### Generate a JSON report

Dockerfile scan:

```bash
guardrail scan \
  --dockerfile tests/fixtures/misconfigured/Dockerfile \
  --json-report reports/dockerfile-scan.json
```

Dependency scan:

```bash
guardrail scan \
  --requirements requirements.txt \
  --json-report reports/dependency-scan.json
```

On Windows PowerShell, these commands can also be entered on one line.

The parent directory for a report must already exist. For example, create it with:

```powershell
New-Item -ItemType Directory -Force reports
```

### Example JSON report

A clean scan produces a report similar to:

```json
{
  "tool": "GuardRail",
  "status": "PASS",
  "finding_count": 0,
  "findings": []
}
```

When findings are detected, the report includes details for each finding. Dependency findings and Dockerfile findings use different fields appropriate to their scanners.

## Exit codes

| Exit code | Meaning |
|---|---|
| `0` | Scan completed with no findings (`PASS`). |
| `1` | Findings were detected (`BLOCK`). |
| `2` | A scan or report-generation error occurred (`ERROR`). |

These exit codes allow GuardRail to be used as a security gate in automated workflows.

## Development and testing

Install the development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the test suite:

```bash
python -m pytest
```

Run Ruff:

```bash
python -m ruff check .
```

The project includes tests for the CLI, dependency scanner, Dockerfile scanner, and JSON reporting. GitHub Actions runs tests and lint checks on pushes and pull requests targeting `main`.

## Project structure

```text
guardrail/
├── .github/
│   └── workflows/
│       └── ci.yml
├── src/
│   └── guardrail/
│       ├── cli.py
│       ├── dependency_scanner.py
│       ├── dockerfile_scanner.py
│       └── reporting.py
├── tests/
│   ├── fixtures/
│   ├── test_cli.py
│   ├── test_dependency_scanner.py
│   ├── test_dockerfile_scanner.py
│   └── test_reporting.py
├── policies/
├── docs/
├── pyproject.toml
└── README.md
```

## Limitations

- Dockerfile checks use static pattern matching and do not fully interpret Dockerfile syntax.
- The scanner does not resolve every possible username or UID to determine whether it represents root.
- Dependency results depend on the vulnerability information available to `pip-audit` at scan time.
- A clean scan means no findings were detected by the implemented checks; it does not guarantee that an application or container is secure.
- GuardRail is an early-stage project and is not a replacement for a comprehensive security assessment.

## Roadmap

Potential future improvements include:

- Additional Dockerfile security policies.
- More comprehensive and isolated dependency-scanner tests.
- Security checks for GitHub Actions workflow files.
- Improved finding deduplication and reporting.

## License

No license has been specified yet. Check the repository for a license file before reusing or redistributing this project.
