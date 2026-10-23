
import json
from pathlib import Path
from typing import Any


def write_json_report(
    output_path: str | Path,
    *,
    status: str,
    findings: list[dict[str, Any]],
) -> None:
    """Write scan results as a JSON report."""
    report = {
        "tool": "GuardRail",
        "status": status,
        "finding_count": len(findings),
        "findings": findings,
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
