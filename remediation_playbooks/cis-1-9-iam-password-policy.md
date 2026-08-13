# Remediation: CIS 1.9 — IAM Account Password Policy Missing

## Finding

**Severity:** HIGH
**Resource:** AWS Account (account-level setting)
**Issue:** No IAM account password policy is configured. Users can set weak, short,
or never-expiring passwords with no complexity requirements.

## Why This Is Dangerous

Without a password policy, any IAM user with console access can choose a trivially
guessable password (e.g., `password123`). This makes brute-force and credential-stuffing
attacks viable. CIS Benchmark 1.9 requires organizations to enforce minimum password
length, complexity, and rotation to reduce this attack surface.

## Remediation — AWS CLI

```bash
# Set a strong password policy in a single command
aws iam update-account-password-policy \
    --minimum-password-length 14 \
    --require-symbols \
    --require-numbers \
    --require-uppercase-characters \
    --require-lowercase-characters \
    --max-password-age 90 \
    --password-reuse-prevention 24 \
    --allow-users-to-change-password
```

### What each flag does:

| Flag | Effect |
|---|---|
| `--minimum-password-length 14` | Passwords must be at least 14 characters |
| `--require-symbols` | Must contain at least one special character (`!@#$%` etc.) |
| `--require-numbers` | Must contain at least one digit |
| `--require-uppercase-characters` | Must contain at least one uppercase letter |
| `--require-lowercase-characters` | Must contain at least one lowercase letter |
| `--max-password-age 90` | Passwords expire after 90 days |
| `--password-reuse-prevention 24` | Cannot reuse any of the last 24 passwords |
| `--allow-users-to-change-password` | Users can change their own password |

## Remediation — Terraform

```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  allow_users_to_change_password = true
}
```

## Verification

```bash
# Confirm the policy is now active
aws iam get-account-password-policy

# Expected output should show:
#   "MinimumPasswordLength": 14
#   "RequireSymbols": true
#   "RequireNumbers": true
#   "RequireUppercaseCharacters": true
#   "RequireLowercaseCharacters": true
#   "MaxPasswordAge": 90
#   "PasswordReusePrevention": 24
```

## Deployment Impact

- **Setting a password policy does NOT invalidate existing passwords.** Users with
  weak passwords will only be forced to comply on their next password change or when
  their current password expires (after `max-password-age` days).
- **To force immediate compliance**, combine this with a password expiration reset
  for all console users — but coordinate with the team first, as it will lock out
  users who don't update promptly.
- **No downtime risk.** This is an account-level IAM setting that does not affect
  running services, API access, or access keys — it only governs console password rules.
- **Safe to deploy immediately** in most environments.
