
import argparse


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="guardrail",
        description="Scan a repository for security-policy violations.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="guardrail 0.1.0",
    )

    parser.parse_args()


if __name__ == "__main__":
    main()
