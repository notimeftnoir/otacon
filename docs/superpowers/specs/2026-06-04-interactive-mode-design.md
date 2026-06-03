# Interactive Mode — Design Spec

**Date:** 2026-06-04  
**Status:** Approved  

## Problem

Running `otacon` bare shows help text. The goal is to replace that with an interactive prompt so the tool is immediately usable without memorising subcommands or flags.

## Goal

When `otacon` is invoked with no arguments, it enters an interactive mode that:
1. Asks for a domain
2. Lets the user pick a mode (scan / generate) via an arrow-key menu with `[*]` as the selection indicator
3. Asks one or two mode-specific options
4. Runs the chosen command with existing output rendering (progress bar, table, etc.)

## Architecture

Two-file change. No existing logic is duplicated.

```
cli.py          ← one-line change: bare invocation → interactive.run()
interactive.py  ← NEW: full interactive flow
pyproject.toml  ← adds questionary to dependencies
```

`interactive.py` exposes a single public function `run()`. Internally it builds parameters and delegates to the existing `permutations`, `scoring`, `resolver`, and `reporters` modules — no logic is copied.

## Interactive Flow

### Shared (both modes)

1. Show banner (existing `_banner()`)
2. `questionary.text` — "Domain:" with inline validation (non-empty; warns but allows domains without a TLD)
3. `questionary.select` — "Mode:" with `[*]` pointer
   - `scan    — DNS + HTTP, detects registered variants`
   - `generate — offline variants, no network`

### Scan branch

4. `questionary.select` — "Network:"
   - `[*] DNS + HTTP  (full, slower)`
   - `    DNS only    (fast)`
5. `questionary.confirm` — "Show unregistered variants? (y/N)" — default No

Then: runs `_run_scan()` with the collected parameters and renders the existing progress bar + table.

### Generate branch

4. `questionary.text` — "Result limit (0 = all):" — default `"0"`, validated as non-negative integer

Then: calls `permutations.generate()` and renders the existing variant table.

## Selection Indicator

`[*]` — replaces the default `❯` in questionary's style config.

## Error Handling

| Situation | Behaviour |
|---|---|
| Empty / whitespace domain | questionary rejects inline, no exit |
| Domain without TLD | Inline warning, continues |
| Ctrl+C at any point | Clean exit, code 0, no traceback |
| Network errors during scan | Handled by existing `Resolver` — no change |

## Dependencies

Add to `[project.dependencies]` in `pyproject.toml`:
```
questionary>=2.0.0
```

## Out of Scope

- `--exclude` / `--exclude-file` in interactive mode (still available via CLI args)
- `--concurrency` tuning in interactive mode
- `--json` / `--markdown` output in interactive mode
- Any changes to `scan` or `generate` subcommands when called directly
