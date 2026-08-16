#!/usr/bin/env python3
"""
Cloud Audit Pipeline — Automated CSPM execution, filtering, and remediation.

Runs Cloud Custodian policies in --dryrun mode against a target cloud environment,
filters the results by severity, and generates an executive report (HTML or CSV).

Usage:
    uv run python pipeline.py <target_environment> <compliance_framework> <severity_filter> <output_format>

Example:
    uv run python pipeline.py sandbox-01 cis CRITICAL html
"""

import argparse
import csv
import datetime
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request


# ─── Policy metadata ────────────────────────────────────────────────────────────
# Custodian's YAML `tags` field is schema-reserved (expects list[str]), so the
# severity and CIS-ID mapping lives here in Python, keyed by policy name.

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


# ─── Logging helpers ────────────────────────────────────────────────────────────

def log_info(msg):
    """Print an informational log line."""
    print(f"[INFO] {msg}")


def log_warn(msg):
    """Print a warning log line."""
    print(f"[WARN] {msg}")


def log_error(msg):
    """Print an error log line to stderr."""
    print(f"[ERROR] {msg}", file=sys.stderr)


# ─── Argument parsing & validation ──────────────────────────────────────────────

def parse_args():
    """Parse the 4 required positional CLI arguments."""
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


def validate_args(args):
    """
    Validate all arguments and exit with clean messages on bad input.
    Normalizes casing after validation (framework→lower, severity→upper, format→lower).
    """
    errors = []

    if args.compliance_framework.lower() not in VALID_FRAMEWORKS:
        errors.append(
            f"Unsupported compliance framework '{args.compliance_framework}'. "
            f"Supported: {', '.join(VALID_FRAMEWORKS)}"
        )

    if args.severity_filter.upper() not in SEVERITY_LEVELS:
        errors.append(
            f"Invalid severity filter '{args.severity_filter}'. "
            f"Must be one of: {', '.join(SEVERITY_LEVELS)}"
        )

    if args.output_format.lower() not in VALID_FORMATS:
        errors.append(
            f"Unsupported output format '{args.output_format}'. "
            f"Supported: {', '.join(VALID_FORMATS)}"
        )

    if errors:
        for err in errors:
            log_error(err)
        sys.exit(1)

    # Normalize casing for internal use
    args.compliance_framework = args.compliance_framework.lower()
    args.severity_filter = args.severity_filter.upper()
    args.output_format = args.output_format.lower()


# ─── Environment / authentication ───────────────────────────────────────────────

def check_environment():
    """
    Verify required AWS environment variables are set.
    Credentials must NEVER be hardcoded — this is a zero-grade offense.
    """
    required_vars = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION"]
    missing = [v for v in required_vars if not os.environ.get(v)]

    if missing:
        log_error(f"Missing required environment variables: {', '.join(missing)}")
        log_error("Set them before running the pipeline. See .env.example for reference.")
        sys.exit(1)


def find_custodian_binary():
    """
    Locate the custodian CLI binary. When running under `uv run`, it should
    be on PATH from the virtual environment.
    """
    path = shutil.which("custodian")
    if path:
        return path

    # Fallback: look in the project's .venv/bin
    venv_path = os.path.join(".venv", "bin", "custodian")
    if os.path.isfile(venv_path):
        return venv_path

    return None


# ─── Custodian execution with exponential backoff ───────────────────────────────

def run_custodian_policy(custodian_bin, policy_file, output_dir, max_retries=3):
    """
    Run a single Custodian policy via subprocess in --dryrun mode.
    Implements exponential backoff on rate-limit or timeout errors.

    Returns True on success, False on failure after all retries.
    """
    cmd = [custodian_bin, "run", "--dryrun", "--cache-period", "0", "-s", output_dir, policy_file]

    for attempt in range(max_retries):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                return True

            stderr = result.stderr.strip()

            # Detect rate-limit errors and retry with backoff
            if "Throttling" in stderr or "Rate exceeded" in stderr or "RequestLimitExceeded" in stderr:
                wait = 2 ** (attempt + 1)
                log_warn(
                    f"Rate limited on {policy_file}. "
                    f"Backing off {wait}s before retry ({attempt + 1}/{max_retries})..."
                )
                time.sleep(wait)
                continue

            # Non-rate-limit error — log and fail immediately
            log_error(f"Custodian failed for {policy_file}: {stderr}")
            return False

        except subprocess.TimeoutExpired:
            wait = 2 ** (attempt + 1)
            log_warn(
                f"Timeout running {policy_file}. "
                f"Backing off {wait}s ({attempt + 1}/{max_retries})..."
            )
            time.sleep(wait)

    log_error(f"Failed to run {policy_file} after {max_retries} retries.")
    return False


# ─── Output parsing ─────────────────────────────────────────────────────────────

def parse_custodian_results(output_dir, policy_name):
    """
    Read Custodian's resources.json for a given policy.
    Returns the list of matched (failing) resources, or an empty list.

    Custodian writes output to: <output_dir>/<policy_name>/resources.json
    """
    resources_file = os.path.join(output_dir, policy_name, "resources.json")

    if not os.path.exists(resources_file):
        return []

    try:
        with open(resources_file, "r") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, IOError) as e:
        log_warn(f"Could not parse {resources_file}: {e}")
        return []


# ─── Severity filtering ─────────────────────────────────────────────────────────

def severity_meets_threshold(finding_severity, threshold):
    """Returns True if the finding's severity is at or above the threshold."""
    return SEVERITY_LEVELS.index(finding_severity) >= SEVERITY_LEVELS.index(threshold)


# ─── Resource identification ────────────────────────────────────────────────────

def get_resource_identifier(resource, policy_name):
    """Extract a human-readable name from a Custodian resource dict."""
    # S3 buckets
    if "Name" in resource:
        return resource["Name"]
    # IAM users
    if "UserName" in resource:
        return resource["UserName"]
    # EC2 Security Groups
    if "GroupName" in resource and "GroupId" in resource:
        return f"{resource['GroupName']} ({resource['GroupId']})"
    # Account-level findings (password policy)
    if "account_id" in resource:
        return f"account:{resource['account_id']}"
    # Generic fallback
    return json.dumps(resource, default=str)[:80]


# ─── HTML report generation ─────────────────────────────────────────────────────

def generate_html_report(findings, args, report_path):
    """Generate a premium dark-themed HTML executive report."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_str = datetime.datetime.now().strftime("%B %d, %Y")

    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in findings if f["severity"] == "LOW")
    policies_scanned = len(POLICY_METADATA)
    total_findings = len(findings)

    # Build finding cards
    finding_cards = ""
    for i, f in enumerate(findings):
        sev = f["severity"].lower()
        icon = {
            "critical": "&#x26A0;",  # ⚠
            "high": "&#x2622;",      # ☢
            "medium": "&#x25C6;",    # ◆
            "low": "&#x2139;",       # ℹ
        }.get(sev, "&#x25CF;")

        finding_cards += f'''
        <div class="finding-card">
          <div class="finding-header">
            <div class="finding-id">
              <span class="cis-badge">{f["cis_id"]}</span>
              <span class="status-pill sev-{sev}">{icon} {f["severity"]}</span>
            </div>
          </div>
          <h3 class="finding-title">{f["title"]}</h3>
          <div class="finding-resource">
            <span class="resource-label">Affected Resource</span>
            <code class="resource-value">{f["resource"]}</code>
          </div>
          <div class="finding-footer">
            <span class="playbook-link">&#x1F4D6; Remediation playbook available</span>
          </div>
        </div>'''

    empty_state = '''
        <div class="empty-state">
          <div class="empty-icon">&#x2705;</div>
          <h3>All Clear</h3>
          <p>No misconfigurations found at or above the selected severity threshold.</p>
        </div>'''

    # Severity breakdown bar data
    sev_bar_data = []
    if critical_count:
        sev_bar_data.append(("critical", critical_count))
    if high_count:
        sev_bar_data.append(("high", high_count))
    if medium_count:
        sev_bar_data.append(("medium", medium_count))
    if low_count:
        sev_bar_data.append(("low", low_count))

    donut_segments = ""
    cumulative_pct = 0
    if total_findings > 0:
        for sev_class, count in sev_bar_data:
            pct = count / total_findings * 100
            offset = -cumulative_pct
            donut_segments += f'<circle class="donut-segment seg-{sev_class}" cx="21" cy="21" r="15.9155" fill="transparent" stroke-width="6" stroke-dasharray="{pct} {100-pct}" stroke-dashoffset="{offset}"></circle>'
            cumulative_pct += pct

    bar_legend = ""
    legend_items = [
        ("critical", "Critical", critical_count),
        ("high", "High", high_count),
        ("medium", "Medium", medium_count),
        ("low", "Low", low_count),
    ]
    for sev_class, label, count in legend_items:
        if count > 0:
            bar_legend += f'''
            <div class="legend-item">
              <span class="legend-dot dot-{sev_class}"></span>
              <span class="legend-label">{label}</span>
              <span class="legend-count">{count}</span>
            </div>'''

    # Generate horizontal bars for Domain and Resource distributions
    domain_counts = {}
    resource_counts = {}
    for f in findings:
        domain = f.get("domain", "General")
        res = f.get("resource_type", "Unknown")
        domain_counts[domain] = domain_counts.get(domain, 0) + 1
        resource_counts[res] = resource_counts.get(res, 0) + 1
    
    def generate_hz_bars(counts_dict):
        if not counts_dict:
            return '<div class="hz-bar-row"><div class="hz-label"><span>No findings</span></div></div>'
        max_val = max(counts_dict.values())
        out_html = ""
        for name, count in sorted(counts_dict.items(), key=lambda x: x[1], reverse=True):
            pct = count / max_val * 100
            out_html += f'''
            <div class="hz-bar-row">
              <div class="hz-label"><span>{name}</span> <span>{count}</span></div>
              <div class="hz-track"><div class="hz-fill" style="width: {pct:.1f}%"></div></div>
            </div>'''
        return out_html

    domain_bars = generate_hz_bars(domain_counts)
    resource_bars = generate_hz_bars(resource_counts)

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cloud Audit Report — {args.target_environment}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,420;9..144,500;9..144,600&family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {{
    --ink: #17120F;
    --panel: #241C17;
    --panel-raised: #2C221B;
    --line: #3B2E23;
    --parchment: #EDE6D6;
    --parchment-dim: #B7AB96;
    --brass: #B08D57;
    --brass-dim: #7C6640;
    --ember: #C4622D;
    --ember-bright: #E38547;
    --moss: #7C8F5E;
    --moss-bright: #9CB37C;
    --gold: #E8C468;
    --chestnut: #7A3B24;
    --font-display: 'Fraunces', serif;
    --font-body: 'IBM Plex Sans', -apple-system, sans-serif;
    --font-mono: 'IBM Plex Mono', ui-monospace, monospace;
  }}

  *, *::before, *::after {{ box-sizing: border-box; }}
  html, body {{ margin: 0; padding: 0; }}
  body {{
    background:
      radial-gradient(1200px 600px at 50% -10%, rgba(196,98,45,0.08), transparent 60%),
      var(--ink);
    color: var(--parchment);
    font-family: var(--font-body);
    -webkit-font-smoothing: antialiased;
    min-height: 100vh;
  }}

  .report {{ max-width: 1100px; margin: 0 auto; padding: 32px 28px 64px; }}

  /* ── header ── */
  .report-header {{
    display: flex; align-items: center; justify-content: space-between;
    padding-bottom: 20px; margin-bottom: 28px;
    border-bottom: 1px solid var(--line);
    flex-wrap: wrap; gap: 16px;
  }}
  .brand {{ display: flex; align-items: center; gap: 14px; }}
  .brand svg {{ width: 40px; height: 40px; flex: none; }}
  .brand-name {{
    font-family: var(--font-display); font-weight: 600; font-size: 20px;
    letter-spacing: 0.04em; color: var(--parchment); display: block;
  }}
  .brand-sub {{ font-size: 12px; color: var(--parchment-dim); letter-spacing: 0.02em; }}
  .header-meta {{ display: flex; gap: 28px; }}
  .meta-item {{ text-align: right; }}
  .meta-label {{
    display: block; font-size: 10px; text-transform: uppercase;
    letter-spacing: 0.12em; color: var(--brass-dim); margin-bottom: 3px;
  }}
  .meta-value {{ font-family: var(--font-mono); font-size: 15px; color: var(--parchment); }}

  /* ── stat cards ── */
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 14px; margin-bottom: 24px;
  }}
  .stat-card {{
    background: var(--panel); border: 1px solid var(--line);
    border-radius: 10px; padding: 18px 20px;
  }}
  .stat-value {{
    font-family: var(--font-mono); font-size: 32px; font-weight: 600;
    color: var(--parchment); line-height: 1;
  }}
  .stat-label {{
    font-size: 11px; color: var(--brass-dim); text-transform: uppercase;
    letter-spacing: 0.08em; margin-top: 6px;
  }}
  .stat-value.val-critical {{ color: var(--ember-bright); }}
  .stat-value.val-high {{ color: var(--gold); }}
  .stat-value.val-pass {{ color: var(--moss-bright); }}

  /* ── severity chart ── */
  .sev-chart-section {{
    background: var(--panel); border: 1px solid var(--line);
    border-radius: 10px; padding: 24px; margin-bottom: 24px;
    display: flex; align-items: center; gap: 40px; flex-wrap: wrap;
  }}
  .chart-wrapper {{
    position: relative; width: 120px; height: 120px; flex: none;
  }}
  .donut-chart {{ width: 100%; height: 100%; transform: rotate(-90deg); }}
  .donut-segment {{ transition: stroke-dasharray 1s ease, stroke-dashoffset 1s ease; }}
  .donut-track {{ stroke: var(--line); }}
  .chart-center {{
    position: absolute; top: 0; left: 0; right: 0; bottom: 0;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
  }}
  .chart-total {{ font-family: var(--font-mono); font-size: 28px; font-weight: 600; color: var(--parchment); line-height: 1; }}
  .chart-label {{ font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--brass-dim); margin-top: 4px; }}
  .seg-critical {{ stroke: var(--ember); background: var(--ember); }}
  .seg-high {{ stroke: var(--gold); background: var(--gold); }}
  .seg-medium {{ stroke: var(--brass); background: var(--brass); }}
  .seg-low {{ stroke: var(--parchment-dim); background: var(--parchment-dim); }}
  .seg-pass {{ stroke: var(--moss); background: var(--moss); }}
  .legend-container {{ flex: 1; min-width: 200px; }}
  .sev-bar-title {{
    font-family: var(--font-body); font-weight: 600; font-size: 12px;
    text-transform: uppercase; letter-spacing: 0.09em; color: var(--brass);
    margin: 0 0 16px;
  }}
  .bar-legend {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 16px;
  }}
  .legend-item {{ display: flex; align-items: center; gap: 6px; font-size: 12px; }}
  .legend-dot {{
    width: 8px; height: 8px; border-radius: 50%; flex: none;
  }}
  .dot-critical {{ background: var(--ember); }}
  .dot-high {{ background: var(--gold); }}
  .dot-medium {{ background: var(--brass); }}
  .dot-low {{ background: var(--parchment-dim); }}
  .dot-pass {{ background: var(--moss); }}
  .legend-label {{ color: var(--parchment-dim); }}
  .legend-count {{ font-family: var(--font-mono); font-weight: 600; color: var(--parchment); }}

  /* ── horizontal bar graphs ── */
  .chart-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 24px; margin-bottom: 24px; }}
  .panel-section {{ background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 24px; }}
  .hz-bar-row {{ margin-bottom: 14px; }}
  .hz-bar-row:last-child {{ margin-bottom: 0; }}
  .hz-label {{ font-size: 11px; color: var(--parchment-dim); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; display: flex; justify-content: space-between; font-weight: 600; }}
  .hz-track {{ height: 6px; background: var(--line); border-radius: 999px; overflow: hidden; }}
  .hz-fill {{ height: 100%; background: var(--ember-bright); border-radius: 999px; transition: width 1s ease; }}

  /* ── findings ── */
  .findings-section {{
    background: var(--panel); border: 1px solid var(--line);
    border-radius: 10px; padding: 20px;
  }}
  .section-title {{
    font-family: var(--font-body); font-weight: 600; font-size: 12px;
    text-transform: uppercase; letter-spacing: 0.09em; color: var(--brass);
    margin: 0 0 16px;
  }}
  .finding-card {{
    background: var(--panel-raised); border: 1px solid var(--line);
    border-radius: 8px; padding: 16px 18px; margin-bottom: 12px;
  }}
  .finding-card:last-child {{ margin-bottom: 0; }}
  .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
  .finding-id {{ display: flex; align-items: center; gap: 10px; }}
  .cis-badge {{
    font-family: var(--font-mono); font-size: 12px; font-weight: 600;
    color: var(--parchment); background: rgba(176,141,87,0.12);
    padding: 3px 10px; border-radius: 4px; letter-spacing: 0.03em;
  }}
  .status-pill {{
    display: inline-flex; align-items: center; gap: 5px;
    font-size: 10.5px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.06em; padding: 4px 10px; border-radius: 999px;
    white-space: nowrap;
  }}
  .sev-critical {{ background: rgba(196,98,45,0.22); color: var(--ember-bright); }}
  .sev-high {{ background: rgba(232,196,104,0.16); color: var(--gold); }}
  .sev-medium {{ background: rgba(176,141,87,0.14); color: var(--brass); }}
  .sev-low {{ background: rgba(124,143,94,0.18); color: var(--moss-bright); }}
  .finding-title {{
    font-size: 14px; font-weight: 500; color: var(--parchment);
    margin: 0 0 10px; line-height: 1.45;
  }}
  .finding-resource {{
    display: flex; flex-direction: column; gap: 4px;
    padding: 10px 12px; background: rgba(0,0,0,0.2);
    border-radius: 6px; margin-bottom: 10px;
  }}
  .resource-label {{
    font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em;
    color: var(--brass-dim);
  }}
  .resource-value {{
    font-family: var(--font-mono); font-size: 13px; font-weight: 500;
    color: var(--parchment); background: none; padding: 0;
  }}
  .finding-footer {{ font-size: 11.5px; color: var(--moss-bright); }}
  .playbook-link {{ opacity: 0.8; }}

  /* ── empty state ── */
  .empty-state {{
    text-align: center; padding: 48px 20px;
  }}
  .empty-icon {{ font-size: 40px; margin-bottom: 12px; }}
  .empty-state h3 {{
    font-family: var(--font-display); font-size: 20px; font-weight: 500;
    color: var(--moss-bright); margin: 0 0 8px;
  }}
  .empty-state p {{ font-size: 13px; color: var(--parchment-dim); margin: 0; }}

  /* ── footer ── */
  .report-footer {{
    margin-top: 24px; padding-top: 16px; border-top: 1px solid var(--line);
    font-size: 11px; color: var(--brass-dim);
    display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px;
  }}

  /* ── responsive ── */
  @media (max-width: 640px) {{
    .report {{ padding: 20px 16px 48px; }}
    .stat-value {{ font-size: 26px; }}
    .report-header {{ flex-direction: column; align-items: flex-start; }}
    .header-meta {{ gap: 20px; }}
    .meta-item {{ text-align: left; }}
  }}

  @media print {{
    body {{ background: #fff; color: #111; }}
    .report {{ padding: 0; }}
    .stat-card, .sev-bar-section, .findings-section, .finding-card {{
      background: #fafafa; border-color: #ddd;
    }}
    .status-pill {{ border: 1px solid currentColor; }}
  }}
</style>
</head>
<body>

<div class="report">

  <header class="report-header">
    <div class="brand">
      <svg viewBox="0 0 40 40" fill="none" aria-hidden="true">
        <circle cx="20" cy="20" r="18" stroke="var(--brass)" stroke-width="1.4"/>
        <path d="M12 28 Q16 14 20 18 T28 12" stroke="var(--ember-bright)" stroke-width="2.2" stroke-linecap="round" fill="none"/>
        <circle cx="20" cy="20" r="3" fill="var(--ember-bright)" opacity="0.7"/>
      </svg>
      <div>
        <span class="brand-name">CLOUD AUDIT</span>
        <span class="brand-sub">Security Posture Report</span>
      </div>
    </div>
    <div class="header-meta">
      <div class="meta-item">
        <span class="meta-label">Environment</span>
        <span class="meta-value">{args.target_environment}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Framework</span>
        <span class="meta-value">{args.compliance_framework.upper()}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Generated</span>
        <span class="meta-value">{date_str}</span>
      </div>
    </div>
  </header>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-value">{policies_scanned}</div>
      <div class="stat-label">Policies Scanned</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{total_findings}</div>
      <div class="stat-label">Findings (&ge; {args.severity_filter})</div>
    </div>
    <div class="stat-card">
      <div class="stat-value val-critical">{critical_count}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card">
      <div class="stat-value val-high">{high_count}</div>
      <div class="stat-label">High</div>
    </div>
  </div>

  <div class="sev-chart-section">
    <div class="chart-wrapper">
      <svg class="donut-chart" viewBox="0 0 42 42">
        <circle class="donut-track" cx="21" cy="21" r="15.9155" fill="transparent" stroke-width="6"></circle>
        {donut_segments}
      </svg>
      <div class="chart-center">
        <span class="chart-total">{total_findings}</span>
        <span class="chart-label">Findings</span>
      </div>
    </div>
    <div class="legend-container">
      <h2 class="sev-bar-title">Severity Breakdown</h2>
      <div class="bar-legend">
        {bar_legend}
      </div>
    </div>
  </div>

  <div class="chart-grid">
    <div class="panel-section">
      <h2 class="sev-bar-title">Findings by Domain</h2>
      {domain_bars}
    </div>
    <div class="panel-section">
      <h2 class="sev-bar-title">Findings by Resource</h2>
      {resource_bars}
    </div>
  </div>

  <section class="findings-section">
    <h2 class="section-title">Findings &mdash; Severity &ge; {args.severity_filter}</h2>
    {finding_cards if finding_cards else empty_state}
  </section>

  <footer class="report-footer">
    <span>Cloud Audit Pipeline &mdash; Automated CSPM Report</span>
    <span>{timestamp}</span>
  </footer>

</div>

</body>
</html>'''

    with open(report_path, "w") as f:
        f.write(html)


# ─── CSV report generation ──────────────────────────────────────────────────────

def generate_csv_report(findings, args, report_path):
    """Generate a CSV executive report."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(report_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "CIS ID", "Severity", "Finding", "Affected Resource",
            "Environment", "Framework", "Timestamp",
        ])
        for finding in findings:
            writer.writerow([
                finding["cis_id"],
                finding["severity"],
                finding["title"],
                finding["resource"],
                args.target_environment,
                args.compliance_framework.upper(),
                timestamp,
            ])


# ─── Main pipeline ──────────────────────────────────────────────────────────────

def main():
    """
    Entry point. Orchestrates the full audit pipeline:
    parse args → validate → authenticate → scan → filter → report.
    """
    args = parse_args()
    validate_args(args)

    # ── Step 1: Authentication check ──
    log_info(f"Authenticating to {args.target_environment}...")
    check_environment()

    # ── Step 2: Locate Custodian binary ──
    custodian_bin = find_custodian_binary()
    if not custodian_bin:
        log_error(
            "'custodian' command not found. "
            "Is c7n installed? Try: uv sync && uv run custodian version"
        )
        sys.exit(1)

    # ── Step 3: Run all policies ──
    log_info(f"Executing CSPM scan against {args.compliance_framework.upper()} benchmarks...")

    output_base = os.path.join("reports", f"scan_{args.target_environment}")
    os.makedirs(output_base, exist_ok=True)

    total_checks = 0
    all_findings = []

    for policy_name, meta in POLICY_METADATA.items():
        total_checks += 1
        policy_path = meta["policy_file"]

        if not os.path.isfile(policy_path):
            log_warn(f"Policy file not found: {policy_path} — skipping.")
            continue

        success = run_custodian_policy(custodian_bin, policy_path, output_base)
        if not success:
            log_warn(f"Skipping {policy_name} due to execution failure.")
            continue

        # Parse matched (failing) resources
        resources = parse_custodian_results(output_base, policy_name)
        for resource in resources:
            all_findings.append({
                "cis_id": meta["cis_id"],
                "severity": meta["severity"],
                "title": meta["title"],
                "policy_name": policy_name,
                "resource": get_resource_identifier(resource, policy_name),
                "resource_type": meta.get("resource_type", "Unknown"),
                "domain": meta.get("domain", "General"),
            })

    log_info(f"Scan complete. {total_checks} checks performed.")

    # ── Step 4: Filter by severity threshold ──
    log_info(f"Filtering results for {args.severity_filter} severity...")

    filtered = [
        f for f in all_findings
        if severity_meets_threshold(f["severity"], args.severity_filter)
    ]

    if filtered:
        log_warn(f"{len(filtered)} misconfigurations found (>= {args.severity_filter}):")
        for f in filtered:
            print(f"       - {f['cis_id']}: {f['title']} [{f['resource']}]")
    else:
        log_info(f"No misconfigurations found at or above {args.severity_filter} severity.")

    # ── Step 5: Generate executive report ──
    os.makedirs("reports", exist_ok=True)
    base_name = f"audit_{args.target_environment}_{args.severity_filter}"
    
    formats_to_gen = ["html", "csv", "json"] if args.output_format.lower() == "all" else [args.output_format.lower()]

    log_info(f"Generating reports: {', '.join(formats_to_gen).upper()}...")

    for fmt in formats_to_gen:
        report_path = os.path.join("reports", f"{base_name}.{fmt}")
        if fmt == "html":
            generate_html_report(filtered, args, report_path)
        elif fmt == "json":
            with open(report_path, "w") as f:
                json.dump(filtered, f, indent=2)
        elif fmt == "csv":
            generate_csv_report(filtered, args, report_path)

    log_info("Reports saved to ./reports/")
    log_info("Relevant remediation playbooks are available in ./remediation_playbooks/")

    if args.webhook_url:
        log_info("Sending webhook notification...")
        color = 0x36A64F  # Green (All clear)
        if len(filtered) > 0:
            if args.severity_filter in ["CRITICAL", "HIGH"]:
                color = 0xFF0000  # Red (Critical/High findings)
            else:
                color = 0xFFA500  # Orange (Medium/Low findings)


        # Group findings by domain
        domain_findings = {}
        for f in filtered:
            dom = f.get("domain", "General")
            if dom not in domain_findings:
                domain_findings[dom] = []
            domain_findings[dom].append(f"• **{f['cis_id']}**: {f['title']}\n  └ `[{f['resource']}]`")

        fields = [
            {
                "name": "Total Findings",
                "value": f"{len(filtered)} (>= {args.severity_filter})",
                "inline": True
            },
            {
                "name": "Policies Scanned",
                "value": str(total_checks),
                "inline": True
            }
        ]

        for dom, f_list in domain_findings.items():
            val = "\n".join(f_list)
            if len(val) > 1024:
                val = val[:1000] + "\n... *(truncated)*"
            fields.append({
                "name": f"📁 {dom}",
                "value": val,
                "inline": False
            })

        embed = {
            "title": f"🚨 Cloud Audit Complete: {args.target_environment}",
            "description": f"The CSPM scan against `{args.compliance_framework.upper()}` benchmarks has finished.",
            "color": color,
            "fields": fields,
            "footer": {
                "text": "Cloud Audit Security Pipeline"
            }
        }

        fallback_msg = f"🚨 **Cloud Audit Complete ({args.target_environment})**: {len(filtered)} findings detected (>= {args.severity_filter})."
        payload = json.dumps({
            "content": "",  # Empty content so only the embed shows
            "embeds": [embed],
            "text": fallback_msg  # Slack fallback
        }).encode("utf-8")
        req = urllib.request.Request(
            args.webhook_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "CloudAudit/1.0"
            }
        )
        try:
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            log_warn(f"Failed to send webhook notification: {e}")

if __name__ == "__main__":
    main()
