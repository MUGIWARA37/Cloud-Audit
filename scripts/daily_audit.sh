#!/usr/bin/env bash
# ─── Cloud Audit — Daily Scheduled Scan ──────────────────────────────
# This script is designed to be called by cron (or systemd timer).
# It loads environment variables, seeds the mock environment (idempotent),
# and runs the full audit pipeline.
#
# Install into cron with:
#   crontab -e
#   0 2 * * * /absolute/path/to/Cloud-Audit/scripts/daily_audit.sh >> /var/log/cloud-audit.log 2>&1
#
# That line runs the audit every day at 02:00 AM.
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

# Resolve the project root (parent of scripts/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load environment variables from .env if present
if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
fi

# Verify required vars are set
for VAR in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION; do
    if [ -z "${!VAR:-}" ]; then
        echo "[ERROR] Missing required environment variable: $VAR" >&2
        exit 1
    fi
done

cd "$PROJECT_DIR"

echo "========================================"
echo "Cloud Audit — Daily Scan"
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"

# Re-seed the mock environment (idempotent — safe to re-run)
echo "[INFO] Seeding mock environment..."
uv run python scripts/seed_vulnerable_env.py

# Run the pipeline — CRITICAL + HIGH findings, HTML report
echo "[INFO] Running audit pipeline..."
uv run python pipeline.py default cis HIGH html

echo "[INFO] Daily audit complete."
