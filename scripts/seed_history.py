# Script to backfill history.json with dummy data
import json
import os
import random
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List

MOCK_TEMPLATES = {
    "CRITICAL": [
        {"cis_id": "2.1.1", "title": "Storage bucket is publicly accessible via bucket policy", "policy_name": "s3-public-buckets", "resource_type": "aws.s3", "domain": "Storage", "prefix": "bucket-"},
        {"cis_id": "1.14", "title": "IAM user has AdministratorAccess with active access key", "policy_name": "iam-overprivileged-users", "resource_type": "aws.iam", "domain": "Identity", "prefix": "user-"}
    ],
    "HIGH": [
        {"cis_id": "1.9", "title": "IAM account password policy is missing or insufficient", "policy_name": "iam-password-policy", "resource_type": "aws.iam", "domain": "Identity", "prefix": "account:"},
        {"cis_id": "4.1", "title": "Security Group allows unrestricted SSH access (0.0.0.0/0 to port 22)", "policy_name": "ec2-open-ssh", "resource_type": "aws.ec2", "domain": "Network", "prefix": "sg-"}
    ],
    "MEDIUM": [
        {"cis_id": "3.1", "title": "CloudTrail log file validation is disabled", "policy_name": "cloudtrail-validation", "resource_type": "aws.cloudtrail", "domain": "Logging", "prefix": "trail-"},
        {"cis_id": "2.1.2", "title": "RDS Instance is publicly accessible", "policy_name": "rds-public", "resource_type": "aws.rds", "domain": "Database", "prefix": "db-"}
    ],
    "LOW": [
        {"cis_id": "1.20", "title": "AWS Support role not created", "policy_name": "support-role", "resource_type": "aws.iam", "domain": "Identity", "prefix": "role-"}
    ]
}

def generate_findings(critical: int, high: int, medium: int, low: int) -> List[Dict[str, Any]]:
    findings = []
    counts = {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low}
    for sev, count in counts.items():
        for i in range(count):
            template = random.choice(MOCK_TEMPLATES[sev])
            res_id = f"{template['prefix']}{random.randint(1000, 9999)}"
            if template["prefix"] == "account:":
                res_id = "account:000000000000"
            findings.append({
                "cis_id": template["cis_id"],
                "severity": sev,
                "title": template["title"],
                "policy_name": template["policy_name"],
                "resource": res_id,
                "resource_type": template["resource_type"],
                "domain": template["domain"]
            })
    return findings

def main() -> None:
    history_path = os.path.join("reports", "history.json")
    os.makedirs("reports", exist_ok=True)
    history = []
    start_date = datetime.now(UTC) - timedelta(days=365)
    critical = 45
    high = 60
    medium = 30
    low = 15
    print("[SEED] Generating 1 year of historical security data...")
    for i in range(365):
        current_date = start_date + timedelta(days=i)
        if random.random() < 0.05:
            critical += random.randint(1, 5)
            high += random.randint(2, 8)
        if random.random() < 0.15 and critical > 7:
            critical -= random.randint(1, 3)
        if random.random() < 0.2 and high > 5:
            high -= random.randint(1, 4)
        if random.random() < 0.15 and medium > 2:
            medium -= random.randint(1, 3)
        if random.random() < 0.1 and low > 0:
            low -= random.randint(1, 2)
        critical = max(critical, 7)
        high = max(high, 5)
        medium = max(medium, 2)
        low = max(low, 0)
        total = critical + high + medium + low
        findings = generate_findings(critical, high, medium, low)
        history.append(
            {
                "date": current_date.strftime("%Y-%m-%d"),
                "timestamp": current_date.isoformat(),
                "total": total,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "findings": findings,
            },
        )
    with open(history_path, "w") as f:
        json.dump(history, f, indent=2)
    print(f"[SEED] Successfully wrote {len(history)} days of data to {history_path}")
    print(
        f"[SEED] Trend went from {history[0]['total']} vulnerabilities down to {history[-1]['total']}.",
    )

if __name__ == "__main__":
    main()
