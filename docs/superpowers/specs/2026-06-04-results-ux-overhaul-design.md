# Results Quality & UX Overhaul — Design Spec

**Date:** 2026-06-04
**Status:** Approved

## Problem

1. **Table readability** — the "Signals" column (`DNS, MX, SSL, HTTP 301`) is a flat string that's hard to scan across rows. Risk is shown as `90 critical` — no visual weight.
2. **Defensive registrations invisible** — when a domain redirects back to the original (e.g. `googel.com → google.com`), there's no indicator. The user can't tell defensive registrations from live phishing sites at a glance.
3. **HTTP scoring imprecise** — HTTP 301 (redirect) scores the same as HTTP 200 (live site), even though a live site is a stronger phishing signal.

## Goal

Redesign the results table for instant visual scanning, add a `⚑` defensive-redirect indicator, and tighten HTTP scoring — without changing the pipeline architecture or adding new dependencies.

## Architecture

Three files change; the pipeline (`permutations → resolver → scoring → reporters`) stays intact.

```
models.py    ← add is_likely_defensive field
scoring.py   ← set is_likely_defensive, tune HTTP score deltas
reporters.py ← full table redesign (Option B)
```

## 1. Model change (`models.py`)

Add one field to `DomainResult`:

```python
is_likely_defensive: bool = False
```

**Set to `True` when:** `redirects_to` is not `None` and the redirect target contains the original scan target (case-insensitive substring match, e.g. `"google.com" in redirects_to`).

Set by `scoring.score()` — not the resolver — so the original domain is available.

## 2. Scoring changes (`scoring.py`)

`score()` receives `result` (a `DomainResult`) and the original `target: str` as a new parameter.

### New signature

```python
def score(result: DomainResult, target: str = "") -> DomainResult:
```

### is_likely_defensive detection

After the early-return for unregistered domains, before point accumulation:

```python
if result.redirects_to and target and target.lower() in result.redirects_to.lower():
    result.is_likely_defensive = True
```

Score is **not** modified — the domain is still flagged at its full risk score. The flag is informational only (displayed in the table).

### HTTP status scoring (revised)

| Status range | Old points | New points | Rationale |
|---|---|---|---|
| 200–299 | +15 | +15 | Active site — unchanged |
| 300–399 | +15 | +10 | Redirect is weaker than live content |
| 400–499 | +5 | +5 | Registered, dead — unchanged |
| 500+ | +5 | +3 | Misconfigured, likely not in use |

### Callers

`scoring.score()` is called in two places:
- `cli._run_scan` → pass `target` from the enclosing scope
- `interactive._scan` → pass `domain` parameter

`scoring.score_all()` updated to accept and forward `target`.

## 3. Table redesign (`reporters.py`)

### Column layout

| Column | Width | Content |
|---|---|---|
| Domain | flexible | Domain name (bold white) + technique as dim subtitle. `⚑ → <redirect>` appended to subtitle when `is_likely_defensive`. |
| Risk | fixed ~10 | Colored mini-bar (8 chars wide) + numeric score |
| DNS | fixed 5 | `✓` (green) or `—` (dim) |
| MX | fixed 5 | `✓` (green) or `—` (dim) |
| SSL | fixed 5 | `✓` (green) or `—` (dim) |
| HTTP | fixed 7 | Status code colored by range, or `—` |

### Risk bar

8-character wide bar: `filled = round(risk_score / 100 * 8)` chars of `█` (U+2588), remainder `░` (U+2591). Entire bar colored with `risk_level.style`. Score number follows the bar.

Example: score 75 → `██████░░ 75` in `danger` color. Score 0 → `░░░░░░░░  0` in `ok` color.

### Defensive indicator

When `result.is_likely_defensive`:
- Subtitle line under domain: `<technique>  ⚑ → <redirects_to>`
- `⚑` styled as `warn` (yellow) — stands out but not alarming

### HTTP color coding

- 200–299: `ok` (green)
- 300–399: `info` (blue)
- 400–499: `muted` (dim)
- 500+: `warn` (yellow)
- None: `muted` `—`

### Footer

```
Permutations: 131 · registered: 58 · med: 13 · high: 20 · crit: 19    ⚑ = likely defensive (redirects to original)
```

Medium count added. Legend for `⚑` on same line, right-aligned.

## 4. Tests

- `test_scoring.py` — add cases: `is_likely_defensive` set when redirect matches target; HTTP 300–399 = +10; HTTP 500+ = +3; `target` param defaults to `""` (backward compat).
- `test_reporters.py` — add cases: bar renders correctly for 0, 50, 100; `⚑` appears in defensive row; HTTP column colors; footer shows medium count.

## Out of Scope

- WHOIS / domain age scoring
- New permutation techniques
- Concurrency control in interactive mode
- CSV / HTML export
