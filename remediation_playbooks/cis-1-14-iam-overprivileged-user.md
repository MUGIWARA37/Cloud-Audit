# Remediation: CIS 1.14 — IAM User With AdministratorAccess and Active Access Key

## Finding

**Severity:** CRITICAL
**Resource:** `legacy-automation-user`
**Issue:** This IAM user has the `AdministratorAccess` managed policy attached and
possesses an active long-lived access key, making it functionally equivalent to a
root account with programmatic access.

## Why This Is Dangerous

An IAM user with `AdministratorAccess` can perform any action on any resource in the
AWS account — create/delete infrastructure, exfiltrate data, modify IAM itself. Combined
with a long-lived access key (which never expires unless manually rotated), a single
leaked key gives an attacker full, persistent control of the entire account. This is
the most common vector for AWS account compromise.

## Remediation — AWS CLI

```bash
# Step 1: Detach the overprivileged AdministratorAccess policy
aws iam detach-user-policy \
    --user-name legacy-automation-user \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Step 2: Attach a scoped-down policy with only the permissions this user actually needs
# (example: read-only access to a specific S3 bucket)
aws iam put-user-policy \
    --user-name legacy-automation-user \
    --policy-name LeastPrivilegePolicy \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    "arn:aws:s3:::authorized-bucket",
                    "arn:aws:s3:::authorized-bucket/*"
                ]
            }
        ]
    }'

# Step 3: Deactivate the existing access key (list keys first to get the ID)
ACCESS_KEY_ID=$(aws iam list-access-keys --user-name legacy-automation-user \
    --query 'AccessKeyMetadata[0].AccessKeyId' --output text)

aws iam update-access-key \
    --user-name legacy-automation-user \
    --access-key-id "$ACCESS_KEY_ID" \
    --status Inactive

# Step 4: After confirming nothing breaks, delete the old key entirely
aws iam delete-access-key \
    --user-name legacy-automation-user \
    --access-key-id "$ACCESS_KEY_ID"

# Step 5 (recommended): Create a fresh, short-lived key or migrate to IAM roles
# If programmatic access is still needed:
aws iam create-access-key --user-name legacy-automation-user
# Distribute the new key securely and store it in a secrets manager, NOT in code.
```

## Remediation — Terraform

```hcl
# Remove AdministratorAccess and replace with least-privilege
resource "aws_iam_user_policy" "legacy_automation_least_privilege" {
  name = "LeastPrivilegePolicy"
  user = "legacy-automation-user"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::authorized-bucket",
          "arn:aws:s3:::authorized-bucket/*"
        ]
      }
    ]
  })
}

# Best practice: migrate from long-lived keys to IAM roles entirely.
# If the consumer is an EC2 instance or Lambda, use an instance profile / execution role.
```

## Verification

```bash
# Confirm AdministratorAccess is no longer attached
aws iam list-attached-user-policies --user-name legacy-automation-user
# Expected: AdministratorAccess should NOT appear in the list

# Confirm no active access keys remain (or only a freshly rotated one)
aws iam list-access-keys --user-name legacy-automation-user
# Expected: Status = "Inactive" on the old key, or the old key deleted entirely

# Test that the user can no longer perform admin actions
aws sts get-caller-identity  # (using the old key — should fail if deactivated)
```

## Deployment Impact

- **Detaching AdministratorAccess** will immediately break any automation or service
  that relies on this user having unrestricted permissions. Before deploying:
  1. Audit CloudTrail logs to identify what API calls this user actually makes.
  2. Build the replacement least-privilege policy from those real-usage patterns.
  3. Apply the scoped policy first, then detach the admin policy.
- **Deactivating the access key** is reversible (can be re-activated). Use this as a
  safe first step — monitor for failures for 24-48 hours before permanently deleting.
- **Recommended approach:** deploy during low-traffic hours, keep the old key in
  "Inactive" state for a rollback window, then delete after validation.
