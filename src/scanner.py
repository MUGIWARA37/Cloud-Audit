import json
import os
import subprocess
import time
from typing import Any, Dict, List

from src.config import SEVERITY_LEVELS
from src.utils import log_error, log_warn


def run_custodian_policy(
    custodian_bin: str,
    policy_file: str,
    output_dir: str,
    max_retries: int = 3,
) -> bool:
    cmd = [
        custodian_bin,
        "run",
        "--dryrun",
        "--cache-period",
        "0",
        "-s",
        output_dir,
        policy_file,
    ]
    for attempt in range(max_retries):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if result.returncode == 0:
                return True
            stderr = result.stderr.strip()
            if (
                "Throttling" in stderr
                or "Rate exceeded" in stderr
                or "RequestLimitExceeded" in stderr
            ):
                wait = 2 ** (attempt + 1)
                log_warn(
                    f"Rate limited on {policy_file}. Backing off {wait}s before retry ({attempt + 1}/{max_retries})...",
                )
                time.sleep(wait)
                continue
            log_error(f"Custodian failed for {policy_file}: {stderr}")
            return False
        except subprocess.TimeoutExpired:
            wait = 2 ** (attempt + 1)
            log_warn(
                f"Timeout running {policy_file}. Backing off {wait}s ({attempt + 1}/{max_retries})...",
            )
            time.sleep(wait)
    log_error(f"Failed to run {policy_file} after {max_retries} retries.")
    return False


def parse_custodian_results(output_dir: str, policy_name: str) -> List[Dict[str, Any]]:
    resources_file = os.path.join(output_dir, policy_name, "resources.json")
    if not os.path.exists(resources_file):
        return []
    try:
        with open(resources_file) as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, IOError) as e:
        log_warn(f"Could not parse {resources_file}: {e}")
        return []


def severity_meets_threshold(finding_severity: str, threshold: str) -> bool:
    return SEVERITY_LEVELS.index(finding_severity) >= SEVERITY_LEVELS.index(threshold)


def get_resource_identifier(resource: Dict[str, Any], policy_name: str) -> str:
    if "Name" in resource:
        return str(resource["Name"])
    if "UserName" in resource:
        return str(resource["UserName"])
    if "GroupName" in resource and "GroupId" in resource:
        return f"{resource['GroupName']} ({resource['GroupId']})"
    if "account_id" in resource:
        return f"account:{resource['account_id']}"
    return json.dumps(resource, default=str)[:80]
