# Makefile for Cloud Audit CSPM Pipeline
ifneq (,$(wildcard .env))
    include .env
    export
endif

ENV       ?= default
FRAMEWORK ?= cis
SEVERITY  ?= LOW
FORMAT    ?= all

.PHONY: audit seed seed-history start stop status clean fmt lint help

## audit: Run the full CSPM audit pipeline
audit:
	uv run python pipeline.py $(ENV) $(FRAMEWORK) $(SEVERITY) $(FORMAT) $(if $(WEBHOOK_URL),--webhook-url $(WEBHOOK_URL))

## seed: Seed LocalStack with vulnerable mock resources
seed:
	uv run python scripts/seed_vulnerable_env.py

## seed-history: Generate 1 year of fake historical trend data
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

## status: Check LocalStack status
status:
	uv run localstack status

## clean: Remove all generated reports and cache files
clean:
	rm -rf reports/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.html" -delete 2>/dev/null || true

## fmt: Format Python code with Ruff
fmt:
	uv tool run ruff format .

## lint: Lint Python code with Ruff
lint:
	uv tool run ruff check --fix .

## help: Show this help message
help:
	@echo "Cloud Audit Commands:"
	@echo "  make audit        - Run the full CSPM pipeline"
	@echo "  make seed         - Seed mock vulnerable resources"
	@echo "  make seed-history - Generate 1 year of fake history data"
	@echo "  make start        - Start LocalStack"
	@echo "  make stop         - Stop LocalStack"
	@echo "  make status       - Check LocalStack status"
	@echo "  make clean        - Delete generated reports"
	@echo "  make fmt          - Format codebase"
	@echo "  make lint         - Lint codebase"

## lint-strict: Run strict linting
lint-strict:
	uv tool run --with boto3-stubs[boto3] mypy --strict .
