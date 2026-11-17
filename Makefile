.PHONY: install dev lint typecheck test demo smoke clean all ci pre-commit

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

pre-commit:
	pre-commit run --all-files

typecheck:
	mypy src

test:
	pytest tests/ -v --cov=aws_network_mcp --cov-report=term-missing

test-quick:
	pytest tests/ -v -x --no-cov

smoke:
	AWS_NETWORK_MCP_DEMO=true pytest tests/test_server_smoke.py -v --no-cov

demo:
	$(PYTHON) -m aws_network_mcp.demo

server:
	AWS_NETWORK_MCP_DEMO=true $(PYTHON) -m aws_network_mcp.server

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} +

ci: lint typecheck test

audit:
	pip-audit

gitleaks:
	gitleaks detect --source . --verbose

checkov:
	checkov -d iam/ --config-file .checkov.yaml --quiet --compact

security: audit gitleaks checkov
