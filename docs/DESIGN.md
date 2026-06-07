# Otacon — Architecture & Design Notes

## Pipeline

```
permutations.py  →  resolver.py  →  scoring.py  →  reporters.py
(variant gen)       (async net)      (risk score)    (output)
```

A scan runs in four sequential stages for each target domain:

1. **`permutations.py`** — generates domain variants using 11 techniques (typo, homoglyph,
   combosquat, TLD-swap, bitsquat, hyphenation, soundsquat, subdomain, vowel-swap, plural,
   IDN/punycode). Operates on the label only; appends the TLD afterwards. Deduplicates and
   strips the original.

2. **`resolver.py`** — checks each variant concurrently (semaphore default 50). Per variant:
   A record (resolves?), MX record (mail-ready?), TLS handshake on :443 (active HTTPS?),
   HTTP/HTTPS probe (status, server header, redirect target, page title). A separate
   semaphore (4) throttles WHOIS lookups; a per-run task cache deduplicates repeat lookups
   in watch mode.

3. **`scoring.py`** — explicit rule-based scoring (0–100), not ML. Each signal adds points:
   technique base (10–25), resolves (+10), MX (+25), SSL (+15), HTTP 2xx (+15) / 3xx (+10)
   / 4xx (+5), fresh registration (<7d +20, <30d +12, <90d +5). Capped at 100. Defensive
   registration detected by parsing the redirect hostname and checking it matches the target.

4. **`reporters.py`** — renders to four formats: rich table (terminal), JSON, Markdown, HTML.
   HTML output is produced by `html_report.py` (Jinja2-free; pure string templates). The
   live table helper exists for streaming output; the transient progress bar is used during
   scanning.

## Why rules, not ML

- **Transparent**: every point increment has a named reason visible in `--verbose` output.
- **Zero training data**: useful on day 1 without a labelled corpus.
- **Auditable**: a pentester can read `scoring.py` in five minutes and understand every
  decision, which matters when presenting findings to a client.
- **Fast to tune**: changing a weight is a one-line edit and takes effect immediately.

## Key design choices

- **Async-first**: `asyncio` + `aiodns` + `httpx.AsyncClient` allow hundreds of concurrent
  checks in seconds. Sequential checks would take minutes.
- **Graceful degradation**: every network call is wrapped; a failure returns a blank/None
  result and does not crash or stall other concurrent checks.
- **`theme.py` as single source of truth**: all colour, emoji, and risk-level thresholds live
  in one file so terminal, HTML, and Markdown outputs stay consistent.
- **`models.py` (Pydantic)**: the `DomainResult` model flows unchanged from resolver through
  scoring through every reporter, giving free JSON serialisation and type safety.
- **Watch mode** (`watch.py`): re-runs the full pipeline on a configurable interval and
  persists state between runs to highlight *new* findings only (`state.py`).
