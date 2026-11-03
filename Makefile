.PHONY: install dev lint typecheck test demo clean all ci

# Default Python
PYTHON ?= python3

all: install lint typecheck test

install:
	$(PYTHON) -m pip install -e .

dev:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	ruff check src tests
	ruff format --check src tests

lint-fix:
	ruff check --fix src tests
	ruff format src tests

typecheck:
	mypy src

test:
	pytest tests/ -v --cov=aws_network_mcp --cov-report=term-missing

test-quick:
	pytest tests/ -v -x --no-cov

demo:
	$(PYTHON) -m aws_network_mcp.demo

server:
	AWS_NETWORK_MCP_DEMO=true $(PYTHON) -m aws_network_mcp.server

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} +

# CI targets
ci: lint typecheck test

# Security scanning
audit:
	pip-audit

gitleaks:
	gitleaks detect --source . --verbose

checkov:
	checkov -d iam/ -d examples/terraform/ --quiet

security: audit gitleaks checkov
