PYTHON ?= python3
RUFF ?= ruff
PIP := $(PYTHON) -m pip
PIP_INSTALL := $(PIP) install --user --break-system-packages
MAIN := src/main.py
SRC_GLOB := src/nodpi/*.py
TEST_GLOB := tests/*.py
DEV_REQUIREMENTS := requirements-dev.txt

.PHONY: help up run run-quiet install-deps compile test lint format ci-check pre-commit install-hooks

help:
	@printf "Available targets:\n"
	@printf "  make up         Run NoDPI with the local runtime config\n"
	@printf "  make run        Alias for make up\n"
	@printf "  make run-quiet  Run NoDPI in quiet mode\n"
	@printf "  make install-deps  Install local development dependencies\n"
	@printf "  make compile    Run Python syntax checks\n"
	@printf "  make test       Run unit tests\n"
	@printf "  make lint       Run ruff checks\n"
	@printf "  make format     Format code with ruff format\n"
	@printf "  make pre-commit Run the checks used by the git pre-commit hook\n"
	@printf "  make ci-check   Run compile + lint + test\n"
	@printf "  make install-hooks  Enable repository git hooks\n"

up:
	$(PYTHON) $(MAIN)

run: up

run-quiet:
	$(PYTHON) $(MAIN) --quiet

install-deps:
	$(PIP_INSTALL) -r $(DEV_REQUIREMENTS)

compile:
	$(PYTHON) -m py_compile $(MAIN) $(SRC_GLOB) $(TEST_GLOB)

test:
	$(PYTHON) -m unittest discover -s tests -v

lint:
	@if command -v $(RUFF) >/dev/null 2>&1; then \
		$(RUFF) check .; \
	elif $(PYTHON) -m ruff --version >/dev/null 2>&1; then \
		$(PYTHON) -m ruff check .; \
	else \
		printf "%s\n" "ruff is required for linting. Install dependencies with: make install-deps"; \
		exit 1; \
	fi

format:
	@if command -v $(RUFF) >/dev/null 2>&1; then \
		$(RUFF) format .; \
	elif $(PYTHON) -m ruff --version >/dev/null 2>&1; then \
		$(PYTHON) -m ruff format .; \
	else \
		printf "%s\n" "ruff is required for formatting. Install dependencies with: make install-deps"; \
		exit 1; \
	fi

pre-commit: ci-check

ci-check: compile lint test

install-hooks:
	chmod +x .githooks/pre-commit
	git config core.hooksPath .githooks
	@printf "Git hooks path: %s\n" "$$(git config --get core.hooksPath)"
