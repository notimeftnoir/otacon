# Otacon — development tasks. Needs `just`: https://github.com/casey/just
#
# `check` mirrors .github/workflows/ci.yml step for step, so a green run here
# means a green pipeline. If a step moves there, move it here too — a shortcut
# that drifts from CI is worse than no shortcut, because it is trusted.

set shell := ["bash", "-euo", "pipefail", "-c"]

[private]
default:
    @just --list

# Editable install plus the test toolchain and the local dev tools.
install:
    pip install -e ".[dev,tooling]"
    pre-commit install

# Install the exact hash-verified versions CI runs against.
install-pinned:
    pip install --require-hashes -r requirements-dev.txt
    pip install -e . --no-deps

# ── the gates, in CI's order ───────────────────────────────────────────

# Every gate CI runs, in CI's order. Stops at the first failure.
check: lint format types docs security test audit
    @echo "all gates passed"

# Lint.
lint:
    ruff check .

# Formatting, checked rather than applied. `just fix` applies it.
format:
    ruff format --check .

# Static types, strict.
types:
    mypy --strict src/otacon

# Docstring coverage.
docs:
    interrogate -c pyproject.toml src/otacon

# Security lint.
security:
    bandit -r src/otacon -ll -ii

# Tests with branch coverage, at the threshold CI enforces.
test:
    pytest --cov=src/otacon --cov-branch --cov-fail-under=85

# Known vulnerabilities in the pinned runtime dependencies.
audit:
    pip-audit -r requirements.txt

# Live-network regression tests, excluded from `test` by default as in CI.
test-network:
    pytest -m network

# Apply every fix ruff can make on its own.
fix:
    ruff check --fix .
    ruff format .

# ── running the thing ──────────────────────────────────────────────────

# The triage console with live CSS reload; pair with `just console` elsewhere.
dev:
    textual run --dev src/otacon/tui/app.py:OtaconTUI

# Logs and key events a full-screen app would otherwise swallow.
console:
    textual console

# Triage a saved report, without touching the network.
tui REPORT:
    otacon tui --from {{REPORT}}

# Scan a domain, passing any extra flags straight through.
scan DOMAIN *ARGS:
    otacon scan {{DOMAIN}} {{ARGS}}

# ── release chores ─────────────────────────────────────────────────────

# Regenerate both lockfiles; they must move together or the two drift apart.
lock:
    uv pip compile --generate-hashes --python-version 3.12 -o requirements.txt requirements.in
    uv pip compile --generate-hashes --python-version 3.12 -o requirements-dev.txt requirements-dev.in

# Build the wheel and sdist.
build:
    python -m build

# Install the built wheel into a throwaway venv and run it, as CI does.
smoke: build
    rm -rf /tmp/otacon-smoke
    python -m venv /tmp/otacon-smoke
    /tmp/otacon-smoke/bin/pip install --quiet dist/*.whl
    /tmp/otacon-smoke/bin/otacon --version
    /tmp/otacon-smoke/bin/otacon generate example.com --limit 3

# Regenerate the README screenshots from a real scan; needs working DNS.
demo DOMAIN="example.com":
    # A host that cannot resolve produces an honest "inconclusive" card rather
    # than a table, which would misrepresent the tool as broken.
    python tools/render_demo_svg.py {{DOMAIN}} assets/brand/demo-scan.svg
    python tools/render_tui_svg.py {{DOMAIN}} assets/brand/demo-tui.svg
