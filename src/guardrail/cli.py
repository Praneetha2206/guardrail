import argparse
import sys
from dataclasses import asdict

from guardrail.dependency_scanner import (
    DependencyScanError,
    scan_dependencies,
)
from guardrail.dockerfile_scanner import scan_dockerfile
from guardrail.reporting import write_json_report


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="guardrail",
        description="A policy-driven DevSecOps security gate.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="guardrail 0.1.0",
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan dependencies and Dockerfile security policies.",
    )
    scan_parser.add_argument(
        "--requirements",
        help="Path to a pip requirements file.",
    )
    scan_parser.add_argument(
        "--dockerfile",
        help="Path to a Dockerfile.",
    )
    scan_parser.add_argument(
        "--json-report",
        help="Write scan results to a JSON file.",
    ) 
    args = parser.parse_args()

    if args.command != "scan":
        parser.print_help()
        return

    if not args.requirements and not args.dockerfile:
        parser.error(
            "scan requires --requirements, --dockerfile, or both."
        )

    all_findings: list[dict] = []
    scan_failed = False

    print("GuardRail security scan")
    print("=======================")

    if args.requirements:
        print("\n[Dependency scan]")

        try:
            findings = scan_dependencies(args.requirements)

            if not findings:
                print("PASS: No known dependency vulnerabilities found.")

            for finding in findings:
                all_findings.append(
                    {
                        "type": "dependency",
                        **asdict(finding),
                    }
                )
                print(
                    f"BLOCK [{finding.vulnerability_id}] "
                    f"{finding.package} {finding.installed_version}"
                )
                print(f"  Description: {finding.description or 'Not provided'}")

                if finding.fix_versions:
                    print(
                        "  Fixed versions: "
                        + ", ".join(finding.fix_versions)
                    )

        except DependencyScanError as exc:
            scan_failed = True
            print(f"ERROR: {exc}", file=sys.stderr)

    if args.dockerfile:
        print("\n[Dockerfile scan]")

        try:
            findings = scan_dockerfile(args.dockerfile)

            if not findings:
                print("PASS: No Dockerfile policy violations found.")

            for finding in findings:
                all_findings.append(
                    {
                        "type": "dockerfile",
                        **asdict(finding),
                    }
                )
                print(
                    f"BLOCK [{finding.rule_id}] "
                    f"{finding.severity} — {finding.message}"
                )
                print(f"  Line: {finding.line_number}")

        except (FileNotFoundError, OSError, UnicodeError) as exc:
            scan_failed = True
            print(f"ERROR: {exc}", file=sys.stderr)

    print("\n=======================")

    
    status = (
        "ERROR"
        if scan_failed
        else "BLOCK"
        if all_findings
        else "PASS"
    )

    if args.json_report:
        try:
            write_json_report(
                args.json_report,
                status=status,
                findings=all_findings,
            )
            print(f"JSON report written to: {args.json_report}")
        except OSError as exc:
            print(
                f"ERROR: Could not write JSON report: {exc}",
                file=sys.stderr,
            )
            sys.exit(2)

    if scan_failed:
        print("ERROR: One or more scans could not be completed.")
        sys.exit(2)

    if all_findings:
        print(f"BLOCK: {len(all_findings)} finding(s) detected.")
        sys.exit(1)

    print("PASS: All requested security checks passed.")
    sys.exit(0)

if __name__ == "__main__":
    main()