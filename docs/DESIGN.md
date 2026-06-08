# Otacon — Architecture & Design Notes

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
                    ┌─────────────────┐
                    │  CLI / TUI      │  (cli.py · interactive.py)
                    │  user input     │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │ permutations.py │  pure function, no I/O
                    │ 11 techniques   │  produces list[Permutation]
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │  resolver.py    │  async I/O (DNS · TLS · HTTP · WHOIS)
                    │  semaphore-     │  one Resolver per scan, reused HTTP pool
                    │  bounded        │
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │  scoring.py     │  pure function, no I/O
                    │  rule-based     │  enriches DomainResult in place
                    │  0–100 score    │
                    └────────┬────────┘
                             ▼
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
       ┌─────────┐      ┌────────┐      ┌─────────┐
       │ table   │      │ JSON   │      │ HTML    │     reporters.py · html_report.py
       │ (rich)  │      │ MD     │      │ report  │
       └─────────┘      └────────┘      └─────────┘
```

Every stage exchanges Pydantic models — `Permutation`, then `DomainResult`, finally aggregated into a `ScanReport`. Each model carries enough information for downstream stages to be **stateless**: a reporter doesn't need to know how a domain was generated or how it got scored.

---

## Module map

| File | Responsibility | I/O? | Lines |
|---|---|---|---|
| `models.py` | Pydantic data models flowing through the pipeline | no | ~100 |
| `theme.py` | Single source of truth for colors, risk levels, banner | no | ~95 |
| `permutations.py` | 11 permutation algorithms; pure functions | no | ~300 |
| `resolver.py` | Async DNS / TLS / HTTP / WHOIS orchestration | **yes** | ~190 |
| `whois.py` | Domain age fetching with graceful degradation | yes | ~60 |
| `scoring.py` | Rule-based 0–100 risk score, transparent reasons | no | ~115 |
| `reporters.py` | Terminal table, JSON, Markdown rendering | output | ~325 |
| `html_report.py` | Self-contained HTML report (Jinja-free) | output | ~250 |
| `state.py` | Baseline JSON persistence for watch mode | filesystem | ~75 |
| `watch.py` | Diff computation, render, webhook notification | network | ~205 |
| `cli.py` | Typer subcommands (`scan`, `watch`, `generate`) | orchestration | ~350 |
| `interactive.py` | Guided prompts, post-scan action loop | terminal | ~420 |
| `_asyncutils.py` | Cross-platform event loop wrapper (Windows fix) | no | ~40 |

Total: ~2,500 lines, ~250 tests.

---

## Why rules, not ML

A pentester or SOC analyst presenting findings to a client cannot afford to say *"the model gave it 87"*. They need to defend every conclusion.

| Property | Rule-based (Otacon) | ML classifier |
|---|---|---|
| **Auditable** | every score = sum of named signals in `risk_reasons` | weights are opaque, often non-monotonic |
| **Zero training data** | useful on day one | needs labeled corpus, ongoing relabeling |
| **Tunable** | one-line change in `scoring.py`, no retrain | retrain + revalidate + reship |
| **Explainable to non-engineers** | "registered 3 days ago + has MX = high" | "the dense layer activated" |
| **Adversarially robust** | no gradient to exploit | model evasion is a research field |
| **Fast** | O(signals) per result, sub-millisecond | depends on inference time |

The trade-off is **recall on novel techniques** — a rule engine can only catch what it's been programmed to look for. Mitigation: the 11 techniques cover every published category in the literature (see [Le Pochat et al., NDSS '19](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_03A-3_LePochat_paper.pdf)), and adding a new one is a ~30-line PR.

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

### Single source of truth for theme
`theme.py` defines the rich palette, risk-level thresholds, icons, and the banner. Terminal, HTML, and Markdown outputs all consult it — changing a color in one place propagates everywhere. This is enforced by importing `RiskLevel` and `OTACON_THEME` from `theme.py` in every renderer.

### Pydantic models as the data contract
`DomainResult` flows unchanged from `resolver.py` through `scoring.py` and into every reporter. Each stage just *adds* fields (or doesn't). This gives us, for free:
- JSON serialization (`report.model_dump_json()`)
- Validation on baseline load (`state.load_baseline()`)
- Type safety enforced at module boundaries
- An evolving schema that's automatically backwards-compatible (Pydantic ignores unknown fields)

### Graceful degradation everywhere
Every network call is wrapped. A failure returns `None` / `[]` / `False` and the result moves on. **The scan never crashes on a single bad variant** — the user sees the failure as "no signal" in that row, not a stack trace.

The `check_one()` method has a broad `except Exception` at the outermost level. This is deliberate and documented: an unhandled exception there would close the shared `httpx.AsyncClient` and cascade-kill every other concurrent coroutine. We accept the precision loss in exchange for scan integrity.

### Defensive-redirect detection
Brand owners often register their own lookalikes and 301 them back. We detect this in `scoring.py` by parsing the `Location` header from a 3xx response and matching the hostname against the target (exact or subdomain). Flagged with ⚑ in the output and **does not** lower the score — it's informational; the user decides.

### Self-contained HTML report
`html_report.py` produces a single `.html` file with inlined CSS, no JavaScript, no external assets. Hand it to legal, attach it to a ticket, upload it to S3 — it just works. No Jinja2 dependency; we use pure f-strings and `html.escape()`.

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
                    in parallel
                                                                  │
                                                                  ▼
                                                            WHOIS (Semaphore(4))
                                                            cached per-domain
```

Within a single `check_one()`:
1. **A and MX in series** — both DNS, cheap, no benefit from parallelism
2. **SSL and HTTP in `gather()`** — both network-bound, independent, parallel
3. **WHOIS last** — only if registered; bounded by separate semaphore

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
| Webhook delivery failure | `watch.notify` | silently swallowed |
| Baseline file unreadable | `state.load_baseline` | `None` (treated as "no baseline") |

Errors are **not logged by default** — silence is the right behavior when 100 of 150 variants legitimately don't exist. Adding structured logging is on the roadmap behind a `--verbose` flag.

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
| State (baseline) | Tmp paths with `tmp_path` fixture | `pytest` |
| Reporters | Render into a buffered `StringIO`, snapshot the output | `pytest` |
| CLI integration | `typer.testing.CliRunner` for end-to-end command tests | `pytest` |

**No live network in CI** — all 248 tests run offline in ~2 seconds. Live testing happens manually before a release (see commit history for the `microsoft.com` / `github.com` smoke tests).

---

## Performance characteristics

Measured on a residential 100 Mbit connection, `--concurrency 50`, against typical e-commerce / SaaS targets:

| Scenario | Permutations | Time | Notes |
|---|---|---|---|
| `example.com`, DNS-only | ~180 | ~3s | bounded by DNS roundtrip latency |
| `example.com`, full | ~180 | ~12s | WHOIS dominates for registered variants |
| `microsoft.com`, full | ~210 | ~25s | many registered → WHOIS-heavy |
| `github.com`, DNS-only `-c 100` | ~160 | ~2s | concurrency cap relaxed |

Memory: under 100 MB peak even for 200+ permutations. We hold all `DomainResult` objects in memory by design (cheap, simplifies the live table).

---

## Future work

Roadmap items, in rough priority order:

1. **Structured logging** behind `--verbose` — make degraded-result causes visible
2. **Per-permutation-type score weighting via CLI** — let users tune without editing `scoring.py`
3. **Page-content fingerprint comparison** — diff the lookalike's HTML against the target to detect cloned login pages
4. **Async WHOIS batching** — send multiple labels in one connection for TLDs that support it
5. **Screenshot capture** — opt-in, requires headless browser; useful for legal evidence packs
6. **Native i18n target support** — generator currently tuned for ASCII labels
7. **dnstwist baseline import** — read an existing dnstwist JSON as starting baseline for `watch`
8. **Plugin entrypoint for custom techniques** — `pyproject.toml` entry points, no fork needed
