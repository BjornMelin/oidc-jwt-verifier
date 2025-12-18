# =============================================================================
# SOTA 2025 Python Makefile
# Task runner for uv-based Python projects
# Usage: make <target>
# =============================================================================

.PHONY: help install install-dev lint format type-check security test test-cov check clean build

# Default target
.DEFAULT_GOAL := help

# Colors for pretty output
BLUE := \033[34m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m

# =============================================================================
# Help
# =============================================================================

help: ## Show this help message
	@echo "$(BLUE)SOTA 2025 Python Project$(RESET)"
	@echo "========================="
	@echo ""
	@echo "$(GREEN)Available targets:$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(GREEN)Quick start:$(RESET)"
	@echo "  make install-dev  # Install with dev dependencies"
	@echo "  make check        # Run all quality checks"
	@echo "  make test         # Run tests"

# =============================================================================
# Installation
# =============================================================================

install: ## Install package (production dependencies only)
	uv pip install -e .

install-dev: ## Install package with dev dependencies
	uv pip install -e ".[dev]"

sync: ## Sync dependencies from lockfile
	uv sync --all-extras

# =============================================================================
# Code Quality - Linting & Formatting
# =============================================================================

lint: ## Run ruff linter (check only, no fixes)
	@echo "$(BLUE)Running ruff linter...$(RESET)"
	uv run ruff check .

lint-fix: ## Run ruff linter with auto-fix
	@echo "$(BLUE)Running ruff linter with fixes...$(RESET)"
	uv run ruff check . --fix

format: ## Format code with ruff
	@echo "$(BLUE)Formatting code...$(RESET)"
	uv run ruff format .

format-check: ## Check code formatting (no changes)
	@echo "$(BLUE)Checking code format...$(RESET)"
	uv run ruff format . --check

# =============================================================================
# Type Checking
# =============================================================================

type-check: ## Run mypy type checker
	@echo "$(BLUE)Running mypy type checker...$(RESET)"
	uv run mypy

type-check-strict: ## Run mypy with stricter settings
	@echo "$(BLUE)Running mypy (strict mode)...$(RESET)"
	uv run mypy --strict --ignore-missing-imports

# =============================================================================
# Security
# =============================================================================

security: ## Run bandit security scanner
	@echo "$(BLUE)Running bandit security scanner...$(RESET)"
	uv run bandit -c pyproject.toml -r oidc_jwt_verifier/

security-verbose: ## Run bandit with verbose output
	@echo "$(BLUE)Running bandit (verbose)...$(RESET)"
	uv run bandit -c pyproject.toml -r oidc_jwt_verifier/ -v

security-high: ## Run bandit showing only high severity issues
	@echo "$(BLUE)Running bandit (high severity only)...$(RESET)"
	uv run bandit -c pyproject.toml -r oidc_jwt_verifier/ -ll

# =============================================================================
# Testing
# =============================================================================

test: ## Run tests with pytest
	@echo "$(BLUE)Running tests...$(RESET)"
	uv run pytest

test-v: ## Run tests with verbose output
	@echo "$(BLUE)Running tests (verbose)...$(RESET)"
	uv run pytest -v

test-cov: ## Run tests with coverage report
	@echo "$(BLUE)Running tests with coverage...$(RESET)"
	uv run pytest --cov=oidc_jwt_verifier --cov-report=term-missing --cov-report=html

test-cov-xml: ## Run tests with XML coverage (for CI)
	@echo "$(BLUE)Running tests with XML coverage...$(RESET)"
	uv run pytest --cov=oidc_jwt_verifier --cov-report=xml

test-fast: ## Run tests excluding slow markers
	@echo "$(BLUE)Running fast tests only...$(RESET)"
	uv run pytest -m "not slow"

# =============================================================================
# Combined Quality Checks
# =============================================================================

check: format-check lint type-check security test ## Run all quality checks (CI pipeline)
	@echo "$(GREEN)All checks passed!$(RESET)"

check-fix: format lint-fix type-check security test ## Run all checks with auto-fixes
	@echo "$(GREEN)All checks completed (with fixes applied)$(RESET)"

pre-commit: format lint-fix type-check ## Quick pre-commit checks (no security/tests)
	@echo "$(GREEN)Pre-commit checks passed!$(RESET)"

ci: ## Full CI pipeline (strict, no fixes)
	@echo "$(BLUE)Running CI pipeline...$(RESET)"
	uv run ruff format . --check
	uv run ruff check .
	uv run mypy
	uv run bandit -c pyproject.toml -r oidc_jwt_verifier/
	uv run pytest --cov=oidc_jwt_verifier --cov-report=xml --cov-fail-under=80
	@echo "$(GREEN)CI pipeline passed!$(RESET)"

# =============================================================================
# Build & Release
# =============================================================================

build: clean ## Build package distributions
	@echo "$(BLUE)Building package...$(RESET)"
	uv run python -m build

clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf coverage.xml
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# =============================================================================
# Development Utilities
# =============================================================================

watch-test: ## Run tests in watch mode (requires pytest-watch)
	uv run ptw -- -v

repl: ## Start Python REPL with package loaded
	uv run python -c "from oidc_jwt_verifier import *; print('oidc_jwt_verifier loaded')" && uv run python

tree: ## Show project structure
	@tree -I '__pycache__|*.egg-info|.git|.venv|.pytest_cache|.mypy_cache|.ruff_cache|htmlcov|build|dist' -a
