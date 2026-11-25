.PHONY: help install dev test lint fmt type check wheel docker docker-test smoke clean docs

first: help

help:  ## Show this help
	@grep -E '^[0-9a-zA-Z_-]+:.*?##.*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?##"; OFS = "\t\t"}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ------------------------------------------------------------------------------
# Development

install:  ## Install package
	pip install .

dev:  ## Editable install with dev extras
	pip install -e ".[dev]"

test:  ## Run tests
	python -m pytest -q

lint:  ## Lint new code
	python -m ruff check deniz/kit deniz/cli.py deniz/mcp.py tests

fmt:  ## Format new code
	python -m ruff format deniz/kit deniz/cli.py deniz/mcp.py tests
	python -m ruff check --fix deniz/kit deniz/cli.py deniz/mcp.py tests

type:  ## Type check the core
	python -m mypy deniz/kit --follow-imports=skip

check: lint type test  ## Lint, type and test

smoke:  ## Live sanity check
	python -m deniz version
	python -m deniz providers list
	python -m deniz domain example.com --max-hosts 5 --no-typosquat

docs:  ## Regenerate the provider catalog
	python scripts/providers_doc.py

# ------------------------------------------------------------------------------
# Packaging

wheel:  ## Build a wheel
	python -m pip wheel . --no-deps -w dist

clean:  ## Remove build and cache files
	rm -rf build dist .pytest_cache .ruff_cache .mypy_cache .eggs
	find . -type f -name '*.py[co]' -delete
	find . -type d -name __pycache__ -exec rm -rf {} +

# ------------------------------------------------------------------------------
# Containers

docker:  ## Build the image
	docker build -t deniz:dev .

docker-test:  ## Run the test stage
	docker build --target test -t deniz:test .

uninstall:  ## Uninstall package
	pip uninstall -y deniz
