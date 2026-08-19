# Policies metadata and global constants
POLICY_METADATA = {
    "cis-2-1-1-s3-bucket-public-read": {
        "cis_id": "CIS 2.1.1",
        "severity": "CRITICAL",
        "title": "Storage bucket is publicly accessible via bucket policy",
        "policy_file": "policies/s3-public-buckets.yml",
        "resource_type": "S3 Bucket",
        "domain": "Storage",
    },
    "cis-1-14-iam-user-admin-access-with-key": {
        "cis_id": "CIS 1.14",
        "severity": "CRITICAL",
        "title": "IAM user has AdministratorAccess with active access key",
        "policy_file": "policies/iam-overprivileged-users.yml",
        "resource_type": "IAM User",
        "domain": "Identity & Access",
    },
    "cis-1-9-iam-password-policy-missing": {
        "cis_id": "CIS 1.9",
        "severity": "HIGH",
        "title": "IAM account password policy is missing or insufficient",
        "policy_file": "policies/iam-password-policy.yml",
        "resource_type": "IAM Account",
        "domain": "Identity & Access",
    },
    "cis-4-1-ec2-sg-open-ssh": {
        "cis_id": "CIS 4.1",
        "severity": "HIGH",
        "title": "Security Group allows unrestricted SSH access (0.0.0.0/0 to port 22)",
        "policy_file": "policies/ec2-open-ssh.yml",
        "resource_type": "Security Group",
        "domain": "Compute",
    },
}

SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
VALID_FRAMEWORKS = ["cis"]
VALID_FORMATS = ["html", "csv", "json", "all"]
