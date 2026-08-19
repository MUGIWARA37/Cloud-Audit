*This project has been created during a Cloud Security internship at the OCP Group, as part of the ENSA Khouribga curriculum by hloureda.*

# Cloud Audit

Automated Cloud Security Posture Management (CSPM) pipeline that scans cloud
environments for security misconfigurations, filters findings by severity, and
generates executive reports with actionable remediation playbooks.

## Description

Cloud Audit implements an automated auditing workflow built on
[Cloud Custodian](https://cloudcustodian.io/) and
[LocalStack](https://localstack.cloud/), designed to evaluate cloud infrastructure
against [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks).

**How the pipeline works:**

```
 ┌──────────────┐     ┌──────────────────┐     ┌────────────────┐     ┌────────────┐     ┌────────────┐
 │ Authenticate │────▶│  Run Custodian   │────▶│  Filter by     │────▶│  Track     │────▶│  Generate  │
 │ (env vars)   │     │  policies        │     │  severity      │     │  History   │     │  Reports   │
 │              │     │  (--dryrun)      │     │  threshold     │     │  (JSON DB) │     │  + Notify  │
 └──────────────┘     └──────────────────┘     └────────────────┘     └────────────┘     └────────────┘
```

1. **Authenticate** — reads AWS credentials from environment variables (never hardcoded)
2. **Scan** — runs Cloud Custodian policies in read-only `--dryrun` mode against CIS benchmarks
3. **Filter** — parses the raw JSON output and retains only findings at or above the requested severity
4. **Track** — appends the scan summary to `reports/history.json`, a persistent time-series database
5. **Report** — compiles filtered findings into HTML, CSV, and/or JSON reports (all formats by default)
6. **Notify** — sends a rich Discord/Slack webhook embed with severity-grouped findings
7. **Remediate** — provides per-finding playbooks with exact CLI commands and Terraform code

### CIS Checks Implemented

| CIS ID | Check | Severity |
|---|---|---|
| 2.1.1 | S3 bucket publicly accessible via bucket policy | CRITICAL |
| 1.14 | IAM user with AdministratorAccess and active access key | CRITICAL |
| 1.9 | IAM account password policy missing or insufficient | HIGH |
| 4.1 | Security Group allows unrestricted SSH access (0.0.0.0/0 to port 22) | HIGH |

## Instructions

### Prerequisites

- **Python 3.13+**
- **[uv](https://docs.astral.sh/uv/)** — fast Python package manager
- **Docker** — required to run LocalStack
- **A LocalStack Hobby account** — free tier, sign up at [localstack.cloud](https://app.localstack.cloud/sign-up)

### 1. Clone and install dependencies

```bash
git clone <repository-url>
cd Cloud-Audit
uv sync
```

### 2. Configure LocalStack authentication

```bash
uv run localstack auth set-token <your-hobby-token>
```

### 3. Set up environment variables

```bash
cp .env.example .env
# Edit .env if needed (defaults work for LocalStack)
source .env
```

Or export them directly:

```bash
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566
```

### 4. Start LocalStack

```bash
make start
# or: uv run localstack start -d
```

### 5. Seed the vulnerable mock environment

```bash
make seed
# or: uv run python scripts/seed_vulnerable_env.py
```

This creates three deliberately misconfigured resources inside LocalStack.
The script is idempotent — safe to re-run after every LocalStack restart.

### 6. Run the audit pipeline

```bash
make audit ENV=sandbox-01 FRAMEWORK=cis SEVERITY=CRITICAL FORMAT=html
```

Or directly:

```bash
uv run python pipeline.py sandbox-01 cis CRITICAL html
```

**Arguments:**

| Argument | Description | Valid values |
|---|---|---|
| `target_environment` | Cloud account identifier to audit | Any string (e.g. `default`, `sandbox-01`) |
| `compliance_framework` | Security standard to scan against | `cis` |
| `severity_filter` | Minimum severity to include in the report | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `output_format` | Report output format | `html`, `csv`, `json`, `all` (default: generates all three) |

You can also pass `--webhook-url <URL>` (or set `WEBHOOK_URL` in your `.env`) to receive rich Slack/Discord alerts when the pipeline finishes.

### 7. Seed historical data (optional)

To populate the interactive dashboard with a full year of historical trend data:

```bash
make seed-history
```

### 8. View the report

Reports are saved to `reports/` in timestamped subdirectories. A master dashboard is always available at:

```bash
xdg-open reports/latest.html
```

The `latest.html` dashboard features:
- **Date Search** — pick any date to see that day's severity breakdown (doughnut chart + stats)
- **Line Chart** — total findings trend over the past year
- **Stacked Bar Chart** — severity breakdown (Critical/High/Medium/Low) over time

## Project Structure

The codebase is organized as a modular Python package:

```text
Cloud-Audit/
├── Makefile                # Automation commands (make audit, make seed, make fmt, etc.)
├── pipeline.py             # Main entry point for the CSPM pipeline
├── src/                    # Core modules
│   ├── __init__.py
│   ├── config.py           # Central configuration & CIS rule definitions
│   ├── utils.py            # Argument parsing, logging, and validation
│   ├── scanner.py          # Cloud Custodian execution logic
│   ├── reporter.py         # HTML (Dark theme) & CSV generation logic
│   └── notifications.py    # Webhook integration
├── scripts/                # Utility scripts for seeding mock data
├── policies/               # Cloud Custodian YAML rule definitions
└── remediation_playbooks/  # Markdown guides to fix detected issues
```

## Blocking Cases Handled

### API Rate Limiting

The pipeline implements **exponential backoff** when Cloud Custodian encounters
rate-limit errors from the cloud provider (`Throttling`, `Rate exceeded`,
`RequestLimitExceeded`). It retries up to 3 times with increasing wait times
(2s → 4s → 8s) before failing gracefully with a clear error message. The pipeline
never crashes on a rate limit.

### Authentication Timeouts

Before executing any scan, the pipeline validates that all required environment
variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`) are
present. If any are missing, it exits immediately with a specific error listing which
variables are unset — rather than proceeding and failing mid-scan with a confusing
boto3 traceback.

Subprocess calls to Custodian have a 120-second timeout. If a call times out (e.g. due
to network issues), it is retried with exponential backoff, same as rate limits.

### False Positives in Scan Results

Each Custodian policy is designed with precise filters to minimize false positives:

- **S3 public bucket** — only matches buckets with an explicit `Principal: "*"` in
  the bucket policy, not buckets with ACLs or other access patterns.
- **Overprivileged IAM user** — requires *both* `AdministratorAccess` attached *and*
  an active access key. A user with admin access but no programmatic key, or a key
  but scoped permissions, will not trigger this check.
- **Password policy** — checks for the complete absence of a password policy, not
  for a weak-but-present one.

If a check fails to execute (e.g. unsupported service on LocalStack free tier), the
pipeline logs a warning and continues with the remaining checks rather than aborting
the entire scan.

## Remediation Strategy

### Playbook Structure

Each finding at CRITICAL or HIGH severity has a corresponding remediation playbook in
`remediation_playbooks/`:

```
remediation_playbooks/
├── cis-2-1-1-s3-public-bucket.md
├── cis-1-14-iam-overprivileged-user.md
├── cis-1-9-iam-password-policy.md
└── cis-4-1-ec2-open-ssh.md
```

Every playbook contains five sections:

1. **Finding** — what was detected and why it is dangerous
2. **Remediation (CLI)** — copy-paste-ready `aws` CLI commands to fix the issue
3. **Remediation (Terraform)** — equivalent IaC code for teams using infrastructure as code
4. **Verification** — commands to confirm the fix was applied correctly
5. **Deployment Impact** — what could break, what to monitor, and recommended rollout approach

### Deployment Approach

The pipeline itself is **read-only** — it identifies and reports problems but never
modifies infrastructure. Remediation is a separate, deliberate process:

1. **Triage** — security team reviews the audit report and prioritizes findings
2. **Test** — apply the playbook fix in a staging/sandbox environment first
3. **Schedule** — deploy during a maintenance window for changes that affect access
   (e.g. revoking admin permissions, removing public bucket policies)
4. **Apply** — execute the CLI commands or apply the Terraform plan
5. **Verify** — run the verification commands from the playbook
6. **Re-scan** — run the audit pipeline again to confirm the finding is resolved

This separation ensures that no automated process accidentally revokes access or breaks
running services. The human security team remains in the loop for every change.

## Automation

The pipeline is designed to run unattended on a daily schedule. A cron wrapper script
is provided at `scripts/daily_audit.sh`.

To install the daily schedule:

```bash
crontab -e
# Add this line (runs every day at 02:00 AM):
0 2 * * * /absolute/path/to/Cloud-Audit/scripts/daily_audit.sh >> /var/log/cloud-audit.log 2>&1
```

The wrapper script:
- Loads credentials from `.env`
- Re-seeds the mock environment (idempotent)
- Runs the full pipeline
- Logs all output to `/var/log/cloud-audit.log`

## Resources

### References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) — the security standard this pipeline audits against
- [Cloud Custodian Documentation](https://cloudcustodian.io/docs/) — the CSPM engine used for policy evaluation
- [Cloud Custodian GitHub](https://github.com/cloud-custodian/cloud-custodian) — source code and policy examples
- [LocalStack Documentation](https://docs.localstack.cloud/) — local AWS mock environment
- [AWS CLI Reference](https://docs.aws.amazon.com/cli/latest/) — used in remediation playbooks
