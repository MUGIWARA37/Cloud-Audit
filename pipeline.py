import argparse
import datetime
import json
import os
import sys

from src.config import POLICY_METADATA
from src.notifications import send_webhook_notification
from src.reporter import generate_csv_report, generate_html_report
from src.scanner import (
    parse_custodian_results,
    run_custodian_policy,
    severity_meets_threshold,
    get_resource_identifier,
)
from src.utils import (
    check_environment,
    find_custodian_binary,
    log_error,
    log_info,
    log_warn,
    parse_args,
    validate_args,
)


def main() -> None:
    args = parse_args()
    validate_args(args)
    log_info(f"Authenticating to {args.target_environment}...")
    check_environment()
    custodian_bin = find_custodian_binary()
    if not custodian_bin:
        log_error(
            "'custodian' command not found. Is c7n installed? Try: uv sync && uv run custodian version",
        )
        sys.exit(1)
    log_info(f"Executing CSPM scan against {args.compliance_framework.upper()} benchmarks...")
    output_base = os.path.join("reports", f"scan_{args.target_environment}")
    os.makedirs(output_base, exist_ok=True)
    total_checks = 0
    all_findings = []
    for policy_name, meta in POLICY_METADATA.items():
        total_checks += 1
        policy_path = str(meta["policy_file"])
        if not os.path.isfile(policy_path):
            log_warn(f"Policy file not found: {policy_path} — skipping.")
            continue
        success = run_custodian_policy(custodian_bin, policy_path, output_base)
        if not success:
            log_warn(f"Skipping {policy_name} due to execution failure.")
            continue
        resources = parse_custodian_results(output_base, policy_name)
        for resource in resources:
            all_findings.append(
                {
                    "cis_id": meta["cis_id"],
                    "severity": meta["severity"],
                    "title": meta["title"],
                    "policy_name": policy_name,
                    "resource": get_resource_identifier(resource, policy_name),
                    "resource_type": meta.get("resource_type", "Unknown"),
                    "domain": meta.get("domain", "General"),
                },
            )
    log_info(f"Scan complete. {total_checks} checks performed.")
    log_info(f"Filtering results for {args.severity_filter} severity...")
    filtered = [
        f for f in all_findings if severity_meets_threshold(str(f["severity"]), args.severity_filter)
    ]
    if filtered:
        log_warn(f"{len(filtered)} misconfigurations found (>= {args.severity_filter}):")
        for f in filtered:
            print(f"       - {f['cis_id']}: {f['title']} [{f['resource']}]")
    else:
        log_info(f"No misconfigurations found at or above {args.severity_filter} severity.")

    timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y_%m_%d_%H:%M:%S")
    report_dir = os.path.join("reports", f"report_{timestamp_str}")
    os.makedirs(report_dir, exist_ok=True)

    history_file = os.path.join("reports", "history.json")
    history = []
    if os.path.exists(history_file):
        try:
            with open(history_file) as file:
                history = json.load(file)
        except (json.JSONDecodeError, IOError):
            pass
    today_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    history.append(
        {
            "date": today_str,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total": len(filtered),
            "critical": sum(1 for f in filtered if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in filtered if f["severity"] == "HIGH"),
            "medium": sum(1 for f in filtered if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in filtered if f["severity"] == "LOW"),
        },
    )
    with open(history_file, "w") as file:
        json.dump(history, file, indent=2)

    base_name = f"audit_{args.target_environment}_{args.severity_filter}"
    formats_to_gen = (
        ["html", "csv", "json"]
        if args.output_format.lower() == "all"
        else [args.output_format.lower()]
    )
    log_info(f"Generating reports: {', '.join(formats_to_gen).upper()}...")

    for fmt in formats_to_gen:
        report_path = os.path.join(report_dir, f"{base_name}.{fmt}")
        latest_path = os.path.join("reports", f"latest.{fmt}")
        if fmt == "html":
            generate_html_report(filtered, args, report_path, history, include_history=False)
            generate_html_report(filtered, args, latest_path, history, include_history=True)
        elif fmt == "json":
            with open(report_path, "w") as file:
                json.dump(filtered, file, indent=2)
        elif fmt == "csv":
            generate_csv_report(filtered, args, report_path)

    log_info(f"Reports saved to ./{report_dir}/ and ./reports/latest.html")
    log_info("Relevant remediation playbooks are available in ./remediation_playbooks/")

    if args.webhook_url:
        log_info("Sending webhook notification...")
        send_webhook_notification(args.webhook_url, filtered, args, total_checks)


if __name__ == "__main__":
    main()