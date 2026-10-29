# Otacon — Architecture & Design Notes

_[← back to the README](../README.md)_ · [Usage](USAGE.md) · [Scoring](SCORING.md) · [Output](OUTPUT.md) · [CI/CD](CI.md) · [FAQ](FAQ.md) · [Design](DESIGN.md) · [UI roadmap](UI-ROADMAP.md)

---

This document explains *why* Otacon is built the way it is. For *how to use it*, see the [README](../README.md).

---

## Table of contents

- [Pipeline overview](#pipeline-overview)
- [Module map](#module-map)
- [Why rules, not ML](#why-rules-not-ml)
- [Key design choices](#key-design-choices)
- [Async concurrency model](#async-concurrency-model)
- [Error handling & graceful degradation](#error-handling--graceful-degradation)
- [Data flow](#data-flow)
- [Testing strategy](#testing-strategy)
- [Performance characteristics](#performance-characteristics)
- [Future work](#future-work)

---

## Pipeline overview

```
        ┌──────────────┬──────────────┬──────────────┐
        │  cli/        │  tui/        │  triage/     │   entry points
        │  scan·tui·   │  Textual     │  evidence·   │
        │  generate·   │  console     │  notice·     │
        │  diff        │  (default)   │  rescan      │
        └──────┬───────┴──────┬───────┴──────┬───────┘
               │              │              │
               ▼              │              │
        ┌──────────────┐      │              │
        │ permutations/│      │              │          pure, no I/O
        │ 12 rules +   │      │              │          -> list[Permutation]
        │ IDN encoding │      │              │
        └──────┬───────┘      │              │
               ▼              │              │
        ┌──────────────┐      │              │
        │  engine/     │      │              │          structured concurrency
        │  scanner     │      │              │          + FD-bounded pool
        └──────┬───────┘      │              │
               ▼              │              │
        ┌──────────────┐      │              │
        │  net/        │      │              │          all async I/O lives here
        │  dns · http  │      │              │          resolver fans out per
        │  tls · whois │      │              │          permutation
        │  rdap· dnsbl │      │              │
        │  email_sec   │      │              │
        └──────┬───────┘      │              │
               ▼              │              │
        ┌──────────────┐      │              │
        │  scoring/    │      │              │          pure, no I/O
        │  engine      │      │              │          returns a scored copy
        │  classifiers │      │              │
        └──────┬───────┘      │              │
               ▼              ▼              ▼
        ┌──────────────────────────────────────────────┐
        │  reporters/  console · json · markdown ·      │
        │              html · csv                       │
        └──────────────────────────────────────────────┘
```

Every stage exchanges models from `core/` — `Permutation`, then `DomainResult`, finally aggregated into a `ScanReport`. Each carries enough information for downstream stages to be **stateless**: a reporter does not need to know how a domain was generated or how it got scored. `score()` returns a scored copy rather than mutating its input, so the same result can be re-scored under different weights without a re-scan.

`core/` holds the models, enums and exceptions; `ui/` holds the design tokens and the shared wording; `utils/` holds the trust-boundary validators and resolves which palette is active. Nothing in any of the three imports from a layer above it.

---

## Module map

| Package | Responsibility | I/O? | Lines |
|---|---|---|---|
| `core/` | Models, enums and exceptions flowing through the pipeline | no | 601 |
| `ui/` | Design tokens: the four palettes, glyph degradation, terminal capabilities, and the one spelling of every flag and technique | no | 814 |
| `utils/` | The active palette and the shared trust-boundary validators | no | 338 |
| `permutations/` | 12 permutation rules (incl. regional combosquatting) and IDN encoding; pure | no | 618 |
| `engine/` | Scan orchestration under structured concurrency, bounded by the OS descriptor limit | coordinates | 356 |
| `net/` | Every async probe: DNS, HTTP, TLS, RDAP, WHOIS, DNSBL, mail security, content | **yes** | 1425 |
| `scoring/` | Rule-based 0–100 score with transparent reasons, plus the parked/sinkhole/defensive classifiers | no | 608 |
| `reporters/` | Terminal table, JSON, Markdown, CSV and the self-contained HTML report | output | 1290 |
| `cli/` | Typer subcommands: `scan`, `tui`, `generate`, `diff`, `watch` | orchestration | 1223 |
| `triage/` | What the console acts with: the dossier, the abuse notice, re-probing one row | no | 476 |
| `tui/` | Textual triage console — start, live scan, overview, results, compare, settings | terminal | 2689 |

Alongside them sit a few single-file modules: `history.py` (the directory of past
scans), `config.py` (what the operator decided — settings, allow-list, watchlist),
`diff.py` (report comparison), `ct_logs.py` (Certificate Transparency discovery),
`_splash.py` (the start-up animation) and `_asyncutils.py` (a cross-platform
event-loop wrapper for a Windows socket teardown quirk). The pre-2.0 re-export
shims are gone.

Total: ~11,400 lines of source, 632 test functions.


---

## Why rules, not ML

A pentester or SOC analyst presenting findings to a client cannot afford to say *"the model gave it 87"*. They need to defend every conclusion.

| Property | Rule-based (Otacon) | ML classifier |
|---|---|---|
| **Auditable** | every score = sum of named signals in `risk_reasons` | weights are opaque, often non-monotonic |
| **Zero training data** | useful on day one | needs labeled corpus, ongoing relabeling |
| **Tunable** | a `--weights-file`, or a one-line change in `scoring/config.py`, no retrain | retrain + revalidate + reship |
| **Explainable to non-engineers** | "registered 3 days ago + has MX = high" | "the dense layer activated" |
| **Adversarially robust** | no gradient to exploit | model evasion is a research field |
| **Fast** | O(signals) per result, sub-millisecond | depends on inference time |

The trade-off is **recall on novel techniques** — a rule engine can only catch what it's been programmed to look for. Mitigation: the 12 techniques cover every published category in the literature (see [Le Pochat et al., NDSS '19](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_03A-3_LePochat_paper.pdf)), and adding a new one is a ~30-line PR.

---

## Key design choices

### Async-first
`asyncio` + `aiodns` + `httpx.AsyncClient` allow **hundreds of concurrent checks in seconds**. Sequential checks would take minutes — unacceptable for an interactive tool. The choice cascades: every I/O-touching module is `async def`, every test that exercises real I/O is `pytest-asyncio`.

### Bounded concurrency via semaphores
Two separate semaphores in `Resolver`:
- **Global (`_sem`, default 50)** — DNS + HTTP + TLS. Tunable via `--concurrency`.
- **WHOIS (`_whois_sem`, fixed 4)** — registry servers are aggressive about rate-limiting; we never exceed 4 in flight regardless of `--concurrency`.

### Per-run WHOIS cache
WHOIS is the slowest single operation (~1–5s typical, up to 10s timeout). The resolver caches lookups by domain using `asyncio.Task`, so concurrent `check_one()` calls for the same domain share a single network round-trip. The cache is per-`Resolver`-instance, so each scan starts fresh.

### Single source of truth for the look
`ui/tokens.py` holds the four palettes as pure data — no Rich, no Textual, no I/O — and `ui/emit.py` turns a `Palette` into whatever a given renderer wants: a Rich theme, Textual CSS variables, HTML custom properties, or the terminal theme the README's SVG screenshots are exported with. `ui/copy.py` does the same for words: one spelling of every flag and technique, so a finding is not `[cloned-favicon]` in one surface and `FAVICON` in another. `utils/theme.py` is the thin layer that resolves which palette is active (`--theme`, `OTACON_THEME`, `NO_COLOR`) and renders the banner.

Four surfaces draw the same report — the Rich console, the Textual console, the HTML report and the screenshots — and each used to carry its own hard-coded copy of the colours. A test asserts the four themes are complete, so a surface cannot acquire a colour the others lack.

### Pydantic models as the data contract
`DomainResult` flows unchanged from `net/resolver.py` through `scoring/engine.py` and into every reporter. Each stage just *adds* fields (or doesn't). This gives us, for free:
- JSON serialization (`report.model_dump_json()`)
- Type safety enforced at module boundaries
- An evolving schema that's automatically backwards-compatible (Pydantic ignores unknown fields)

### Graceful degradation everywhere
Every network call is wrapped. A failure returns `None` / `[]` / `False` and the result moves on. **The scan never crashes on a single bad variant** — the user sees the failure as "no signal" in that row, not a stack trace.

The `check_one()` method has a broad `except Exception` at the outermost level. This is deliberate and documented: an unhandled exception there would close the shared `httpx.AsyncClient` and cascade-kill every other concurrent coroutine. We accept the precision loss in exchange for scan integrity.

### Defensive-redirect detection
Brand owners often register their own lookalikes and 301 them back. `scoring/classifiers.py` detects this by parsing the `Location` header from a 3xx response and matching the hostname against the target (exact or subdomain). A match **clears the score to 0** and flags the row `OURS`, on the reasoning that a domain redirecting to you is one you already control. The check deliberately refuses to fire when the variant has an MX record: a redirect costs an attacker nothing to add, and mail is the capability that makes a lookalike dangerous.

### Self-contained HTML report
`reporters/html.py` produces a single `.html` file with inlined CSS, no JavaScript (100% CSP-compliant `default-src 'none'`), pure-CSS table filtering (`All`, `Threats`, `Critical`, `High`, `MX`), and inline SVG risk distribution charts. Domain names are automatically defanged (`[.]`) and link to safe inspection sandboxes (urlscan.io). Hand it to legal, attach it to a ticket, upload it to S3 — it just works. No Jinja2 dependency; we use pure f-strings and `html.escape()`.

### Cross-platform event loop handling
Windows' `ProactorEventLoop` raises `ConnectionResetError` on normal HTTP teardowns. `_asyncutils.py` switches to `SelectorEventLoop` on Windows:
- Python 3.12+: `asyncio.run(coro, loop_factory=SelectorEventLoop)`
- Older: `asyncio.set_event_loop_policy(WindowsSelectorEventLoopPolicy())`

---

## Async concurrency model

```
                            ┌─────────────────────────────┐
                            │  asyncio.as_completed       │
                            │  iterates results as they   │
                            │  arrive (not in submit      │
                            │  order)                     │
                            └──────────────┬──────────────┘
                                           │
            ┌──────────────────────────────┼──────────────────────────────┐
            ▼                              ▼                              ▼
       check_one(p1)                  check_one(p2)                  check_one(p3)
            │                              │                              │
   ┌────────┼─────────┐          ┌────────┼─────────┐          ┌────────┼─────────┐
   ▼        ▼         ▼          ▼        ▼         ▼          ▼        ▼         ▼
  DNS-A   DNS-MX    [SSL          (limited by Semaphore(50))
         (gather)    HTTP]
                    race: fast HTTPS cancels slow HTTP
                                                                  │
                                                                  ▼
                                                            WHOIS / RDAP (Semaphore(4))
                                                            cached per-domain
```

Within a single `check_one()`:
1. **A and MX in series** — both DNS, cheap, no benefit from parallelism
2. **SSL and HTTP race** — started concurrently via `asyncio.wait(FIRST_COMPLETED)`. When HTTPS completes first, the slow HTTP task is cancelled immediately, avoiding redundant network waits.
3. **RDAP / WHOIS last** — only if registered; bounded by separate semaphore

Across `check_one()` calls: bounded by `_sem` (default 50). The user sees registered hits stream into the live table as they arrive (via `asyncio.as_completed`), not after the whole batch finishes.

---

## Error handling & graceful degradation

The principle: **a single bad variant must not affect any other variant**.

| Failure type | Where caught | Result |
|---|---|---|
| DNS timeout / NXDOMAIN | `_resolve_a`, `_resolve_mx` | `[]` |
| TLS handshake failure | `_check_ssl` | `False` |
| HTTP error / unreachable | `_probe_http` | `(None, None, None, None)` |
| WHOIS timeout / parse error | `fetch_domain_age` | `(None, None)` |
| Catastrophic per-variant error | `check_one` outer try | blank `DomainResult` |

Errors are **not logged by default** — silence is the right behavior when 100 of 150 variants legitimately don't exist. Pass `--debug` (alias `--verbose`/`-v`) to surface every degradation event on stderr via a `RichHandler` at `DEBUG` level.

---

## Data flow

```
generate(target, exclude)              cli.scan
  │                                       │
  └──> list[Permutation]                  │
            │                             │
            └──> Resolver.check_one() ────┤
                     │                    │
                     └──> DomainResult ───┘
                              │
                              └──> scoring.score(target=target)
                                       │
                                       └──> DomainResult (enriched in place)
                                                │
                                                └──> ScanReport.results.append()
                                                         │
                                                         └──> reporters / html_report
```

Three immutability boundaries:
1. **`Permutation` is read-only** after generation — describes a candidate, not a result.
2. **`DomainResult`** is *appended to* during resolution and scoring; never replaced.
3. **`ScanReport`** is built incrementally and frozen for rendering.

---

## Testing strategy

| Layer | Approach | Tool |
|---|---|---|
| Pure functions (permutations, scoring, theme) | Property tests + unit tests | `pytest` |
| Resolver | Mock DNS + HTTP via `respx`; assert correct signals are extracted | `pytest-asyncio` + `respx` |
| WHOIS | Patch `asyncwhois.aio_whois` with synthetic responses | `pytest-asyncio` |
| Reporters | Render into a buffered `StringIO`, snapshot the output | `pytest` |
| CLI integration | `typer.testing.CliRunner` for end-to-end command tests | `pytest` |

**No live network in CI** — all 400+ tests run offline in a few seconds. Live testing happens manually before a release (see commit history for the `microsoft.com` / `github.com` smoke tests).

---

## Performance characteristics

Measured on a residential connection at `--concurrency 50` unless noted. "DNS-only"
means `--no-http --no-whois --no-dnsbl --no-ct`; "full" is the default, every check on.

| Scenario | Permutations | Resolving | Time | Notes |
|---|---|---|---|---|
| `example.com`, DNS-only | 239 | 74 | ~3s | bounded by DNS roundtrip latency |
| `example.com`, full | 240 | 75 | ~34s | WHOIS dominates for registered variants |
| `github.com`, DNS-only `-c 100` | 238 | 93 | ~5s | concurrency cap relaxed |
| `github.com`, full | 240 | 123 | ~39s | heavily squatted → WHOIS-heavy |

The gap between the two columns is the whole cost model: DNS fans out and finishes
in seconds, while every *registered* variant then pulls a WHOIS or RDAP lookup that
no amount of concurrency makes free. Reach for `--no-whois` when you want speed and
`--no-http` when you want quiet.

Memory: under 100 MB peak even for 200+ permutations. We hold all `DomainResult` objects in memory by design (cheap, simplifies the live table).

---

## Future work

Interface work has its own plan in [UI-ROADMAP.md](UI-ROADMAP.md) — the
design-token layer, the triage console's hierarchy, and the path for users
who are not security specialists.

Engine items, in rough priority order:

1. **Page-content fingerprint comparison** — diff the lookalike's HTML against the target to detect cloned login pages
2. **Async WHOIS batching** — send multiple labels in one connection for TLDs that support it
3. **Screenshot capture** — opt-in, requires headless browser; useful for legal evidence packs
4. **Native i18n target support** — generator currently tuned for ASCII labels
5. **Plugin entrypoint for custom techniques** — `pyproject.toml` entry points, no fork needed
