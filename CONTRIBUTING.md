# Contributing

## Development setup

```bash
git clone https://github.com/notimeftnoir/otacon.git
cd otacon
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows (PowerShell)
pip install -e ".[dev]"
```

## Running tests

```bash
pytest
```

## Pre-commit hooks

Install them once and the same gates CI enforces run on every commit, in
seconds, instead of failing a 12-job matrix ten minutes after you push:

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files     # first run, or after changing the config
```

## Linting

`pre-commit` covers all of these; run them directly if you prefer:

```bash
ruff check .                   # lint
ruff format --check .          # formatting
mypy --strict src/otacon       # types
bandit -r src/otacon -ll -ii   # security lint
interrogate -c pyproject.toml src/otacon   # docstring coverage
```

All checks must pass before a PR is merged, on Python 3.10–3.13 and on Linux,
macOS and Windows.

## Pull requests

- Keep PRs focused — one logical change per PR
- Add or update tests for any changed behaviour
- Update the relevant docstring or README section if the user-facing interface changes
- `CHANGELOG.md` is maintained by the maintainer; you don't need to edit it

## Code style

- Python 3.10+, type-annotated throughout
- `ruff` enforces style (line length 100, E/F/I/UP/B rules)
- No unnecessary comments — code should be self-explanatory; add a comment only when the *why* is non-obvious

## Security

See [SECURITY.md](SECURITY.md) before reporting a vulnerability.
