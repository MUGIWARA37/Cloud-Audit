import argparse
import json
import urllib.error
import urllib.request
from typing import Any, Dict, List

from src.utils import log_warn


def send_webhook_notification(
    webhook_url: str,
    findings: List[Dict[str, Any]],
    args: argparse.Namespace,
    total_checks: int,
) -> None:
    color = 3581519
    if len(findings) > 0:
        if args.severity_filter in ["CRITICAL", "HIGH"]:
            color = 16711680
        else:
            color = 16753920
    domain_findings: Dict[str, List[str]] = {}
    for f in findings:
        dom = str(f.get("domain", "General"))
        if dom not in domain_findings:
            domain_findings[dom] = []
        domain_findings[dom].append(f"• **{f['cis_id']}**: {f['title']}\n  └ `[{f['resource']}]`")
    fields: List[Dict[str, Any]] = [
        {
            "name": "Total Findings",
            "value": f"{len(findings)} (>= {args.severity_filter})",
            "inline": True,
        },
        {"name": "Policies Scanned", "value": str(total_checks), "inline": True},
    ]
    for dom, f_list in domain_findings.items():
        val = "\n".join(f_list)
        if len(val) > 1024:
            val = val[:1000] + "\n... *(truncated)*"
        fields.append({"name": f"📁 {dom}", "value": val, "inline": False})
    embed = {
        "title": f"🚨 Cloud Audit Complete: {args.target_environment}",
        "description": f"The CSPM scan against `{args.compliance_framework.upper()}` benchmarks has finished.",
        "color": color,
        "fields": fields,
        "footer": {"text": "Cloud Audit Security Pipeline"},
    }
    fallback_msg = f"🚨 **Cloud Audit Complete ({args.target_environment})**: {len(findings)} findings detected (>= {args.severity_filter})."
    payload = json.dumps(
        {"content": "", "embeds": [embed], "text": fallback_msg},
    ).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "CloudAudit/1.0"},
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except urllib.error.URLError as e:
        log_warn(f"Failed to send webhook notification: {e}")
