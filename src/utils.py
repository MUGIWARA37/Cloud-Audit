import argparse
import os
import shutil
import sys
from typing import Any, List, Optional

from src.config import SEVERITY_LEVELS, VALID_FORMATS, VALID_FRAMEWORKS


def log_info(msg: str) -> None:
    print(f"\x1b[92m[INFO]\x1b[0m {msg}")


def log_warn(msg: str) -> None:
    print(f"\x1b[93m[WARN]\x1b[0m {msg}")


def log_error(msg: str) -> None:
    print(f"\x1b[91m[ERROR]\x1b[0m {msg}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cloud Audit — Automated CSPM pipeline",
    )
    parser.add_argument(
        "target_environment",
        help="Cloud account profile or identifier to audit (e.g. 'default', 'sandbox-01')",
    )
    parser.add_argument(
        "compliance_framework",
        help="Security standard to audit against (supported: 'cis')",
    )
    parser.add_argument(
        "severity_filter",
        help="Minimum severity to include: CRITICAL, HIGH, MEDIUM, or LOW",
    )
    parser.add_argument(
        "output_format",
        help="Report format: 'html', 'csv', or 'json'",
    )
    parser.add_argument(
        "--webhook-url",
        help="Optional Slack/Discord webhook URL to send notifications upon completion",
        default=os.environ.get("WEBHOOK_URL"),
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    errors: List[str] = []
    if args.compliance_framework.lower() not in VALID_FRAMEWORKS:
        errors.append(
            f"Unsupported compliance framework '{args.compliance_framework}'. Supported: {', '.join(VALID_FRAMEWORKS)}",
        )
    if args.severity_filter.upper() not in SEVERITY_LEVELS:
        errors.append(
            f"Invalid severity filter '{args.severity_filter}'. Must be one of: {', '.join(SEVERITY_LEVELS)}",
        )
    if args.output_format.lower() not in VALID_FORMATS:
        errors.append(
            f"Unsupported output format '{args.output_format}'. Supported: {', '.join(VALID_FORMATS)}",
        )
    if errors:
        for err in errors:
            log_error(err)
        sys.exit(1)
    args.compliance_framework = args.compliance_framework.lower()
    args.severity_filter = args.severity_filter.upper()
    args.output_format = args.output_format.lower()


def check_environment() -> None:
    required_vars = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION"]
    missing = [v for v in required_vars if not os.environ.get(v)]
    if missing:
        log_error(f"Missing required environment variables: {', '.join(missing)}")
        log_error(
            "Set them before running the pipeline. See .env.example for reference.",
        )
        sys.exit(1)


def find_custodian_binary() -> Optional[str]:
    path = shutil.which("custodian")
    if path:
        return path
    venv_path = os.path.join(".venv", "bin", "custodian")
    if os.path.isfile(venv_path):
        return venv_path
    return None
