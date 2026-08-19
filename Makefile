# Load .env automatically if it exists (no need to source manually)
ifneq (,$(wildcard .env))
    include .env
    export
endif

# ─── Cloud Audit — Makefile ──────────────────────────────────────────
# Execution wrapper for the CSPM audit pipeline.
#
# Usage:
#   make audit ENV=sandbox-01 FRAMEWORK=cis SEVERITY=CRITICAL FORMAT=html
#
# Quick targets:
#   make seed       — seed the vulnerable mock environment
#   make audit      — run the full audit pipeline
#   make clean      — remove generated reports
#   make help       — show available targets
# ─────────────────────────────────────────────────────────────────────

# Default arguments (override on the command line)
ENV       ?= default
FRAMEWORK ?= cis
SEVERITY  ?= LOW
FORMAT    ?= all

.PHONY: audit seed start stop status clean help

## audit: Run the full CSPM audit pipeline
audit:
	uv run python pipeline.py $(ENV) $(FRAMEWORK) $(SEVERITY) $(FORMAT) $(if $(WEBHOOK_URL),--webhook-url $(WEBHOOK_URL))

## seed: Seed the LocalStack environment with vulnerable resources
seed:
	uv run python scripts/seed_vulnerable_env.py

## seed-history: Generate 1 year of fake historical trend data for the dashboard graph
seed-history:
	uv run python scripts/seed_history.py

## start: Start LocalStack in the background
start:
	uv run localstack start -d
	@echo "[INFO] Waiting for LocalStack to be ready..."
	@sleep 10
	uv run localstack status

## stop: Stop LocalStack
stop:
	uv run localstack stop

## status: Check if LocalStack is running
status:
	uv run localstack status

## clean: Remove all generated reports and cache files
clean:
	rm -rf reports/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.html" -delete 2>/dev/null || true

## help: Show this help message
help:
	@echo "Cloud Audit — Available targets:"
	@echo ""
	@echo "  make audit   ENV=sandbox-01 FRAMEWORK=cis SEVERITY=CRITICAL FORMAT=json"
	@echo "               Run the full CSPM pipeline with the given arguments."
	@echo ""
	@echo "  make seed    Seed LocalStack with vulnerable mock resources."
	@echo "  make start   Start LocalStack (Docker) in the background."
	@echo "  make stop    Stop LocalStack."
	@echo "  make status  Check LocalStack status."
	@echo "  make clean   Delete all generated reports."
	@echo ""
	@echo "Full end-to-end example:"
	@echo "  make start"
	@echo "  make seed"
	@echo "  make audit ENV=sandbox-01 SEVERITY=CRITICAL FORMAT=html"
