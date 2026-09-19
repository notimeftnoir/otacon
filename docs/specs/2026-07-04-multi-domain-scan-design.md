# Multi-domain scan — design spec
**Date:** 2026-07-04
**Status:** Approved

## Goal

Allow `otacon scan` to accept multiple domains in a single invocation, scan them sequentially, and produce one aggregated report. Simultaneously remove watch mode (no longer needed — tool is one-shot only).

---

## CLI changes

### Multi-domain input

The positional `domain` argument changes from `str` to `list[str]` (typer variadic). A new `--domains-file / -D` option accepts a path to a plain-text file with one domain per line.

Both sources are merged and deduplicated before the scan begins. Single-domain invocations remain backward compatible.

```bash
# existing — unchanged
otacon scan github.com

# new — multiple positional args
otacon scan github.com google.com example.com

# new — from file
otacon scan --domains-file brands.txt

# combined
otacon scan github.com --domains-file more_brands.txt
```

### Watch mode removal

- Remove `watch` subcommand from `cli.py`
- Delete `src/otacon/watch.py` and `src/otacon/state.py`
- Delete associated tests (`tests/test_watch.py`, `tests/test_state.py`)
- Update README to remove watch mode section

---

## Scan loop

Domains are scanned **sequentially** — full existing scan logic (resolver, scoring, TLS, WHOIS) runs per domain unchanged. Results are collected into `dict[str, ScanReport]`.

Terminal output: existing per-domain streaming table prints for each domain as it runs. After all domains complete, a summary banner prints:

```
Scan complete · 3 domains · 8 registered · crit: 2 · high: 3 · med: 3
github.com    4 hits  crit:1
google.com    3 hits  high:2  med:1
example.com   1 hit   med:1
```

`--fail-on` threshold is evaluated after all domains finish. Exit 1 if **any** domain has a hit at or above the threshold.

---

## Aggregated report

### JSON

```json
{
  "scanned_at": "2026-07-04T12:00:00Z",
  "domains": {
    "github.com": {
      "target": "github.com",
      "started_at": "...",
      "total_permutations": 143,
      "results": [ "...DomainResult dicts..." ],
      "dns_hijack_detected": false
    },
    "google.com": {
      "target": "google.com",
      "started_at": "...",
      "total_permutations": 98,
      "results": [ "...DomainResult dicts..." ],
      "dns_hijack_detected": false
    }
  },
  "summary": {
    "total_registered": 8,
    "critical": 2,
    "high": 3,
    "medium": 3
  }
}
```

### HTML

New summary table at the top (domain | total hits | crit | high | med | low), followed by existing per-domain sections unchanged. Single output file.

### Implementation

`reporters.py` gains `aggregate_json(reports: dict[str, ScanReport]) -> str`.
`html_report.py` gains `aggregate_html(reports: dict[str, ScanReport]) -> str`.
Existing single-domain functions are called internally by the new aggregated ones — not removed.

---

## Error handling

If a domain in the list is invalid or its scan fails:
- Print a Rich warning in the terminal
- Skip it in results and continue remaining domains
- Include it in the summary banner as `ERROR`
- Do not abort the entire scan

---

## Testing

- `test_cli.py` — variadic args, `--domains-file`, deduplication, `--fail-on` across domains
- `test_reporters.py` — `aggregate_json` and `aggregate_html` with a multi-domain fixture
- `test_watch.py`, `test_state.py` — deleted with their modules
- All existing single-domain tests remain unchanged

---

## Out of scope

- Parallel scanning (deliberately excluded — sequential keeps network footprint low)
- Per-domain output files (one aggregated report only)
- Changes to scoring, permutations, or resolver logic
