# Contributing

## Development setup

```bash
git clone https://github.com/notimeftnoir/otacon.git
cd otacon
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows (PowerShell)
pip install -e ".[dev,tooling]"
```

`dev` is the test and lint toolchain; `tooling` adds the local conveniences —
`pre-commit` and `textual-dev` — which are deliberately outside the pinned set
CI installs, since CI runs neither and they bring about thirty-five further
packages with them.

With [`just`](https://github.com/casey/just) on your path, `just install` does
that and installs the hooks, and `just` on its own lists everything else.

To get the exact, hash-verified versions CI runs against instead:

```bash
pip install --require-hashes -r requirements-dev.txt
pip install -e . --no-deps
```

## Dependencies

Runtime dependencies are declared in `pyproject.toml` and pinned with hashes in
`requirements.txt`; the dev toolchain is pinned in `requirements-dev.txt`. After
changing `requirements.in` or `requirements-dev.in`, regenerate **both** lock
files so the two stay in step — the exact `uv pip compile` command is in each
file's header.

## Running tests

```bash
pytest
```

## Pre-commit hooks

Install them once and the same gates CI enforces run on every commit, in
seconds, instead of failing a 12-job matrix ten minutes after you push:

```bash
pre-commit install
pre-commit run --all-files     # first run, or after changing the config
```

## Linting

`just check` runs every gate CI runs, in CI's order, and `pre-commit` covers
the same ground on each commit. Run them directly if you prefer:

```bash
ruff check .                   # lint
ruff format --check .          # formatting
mypy --strict src/otacon       # types
bandit -r src/otacon -ll -ii   # security lint
interrogate -c pyproject.toml src/otacon   # docstring coverage
```

All checks must pass before a PR is merged, on Python 3.12–3.13 and on Linux,
macOS and Windows.

## Pull requests

- Keep PRs focused — one logical change per PR
- Add or update tests for any changed behaviour
- Update the relevant docstring or README section if the user-facing interface changes
- `CHANGELOG.md` is maintained by the maintainer; you don't need to edit it

## Code style

- Python 3.12+, type-annotated throughout
- `ruff` enforces style (line length 100; rule sets E, W, F, I, UP, B, N, S, SIM and RUF —
  see `[tool.ruff.lint]` in `pyproject.toml` for the exact selection and the documented ignores)
- No unnecessary comments — code should be self-explanatory; add a comment only when the *why* is non-obvious

## Security

See [SECURITY.md](SECURITY.md) before reporting a vulnerability.
