# Output formats

_[← back to the README](../README.md)_ · [Usage](USAGE.md) · [Scoring](SCORING.md) · [Output](OUTPUT.md) · [CI/CD](CI.md) · [FAQ](FAQ.md) · [Design](DESIGN.md)

---

One scan, five ways to consume it. Pick the one that fits your workflow:

| Format | Flag | Best for |
|---|---|---|
| **Rich terminal table** | *(default)* | Interactive triage — colors, risk bars, live streaming as hits arrive |
| **JSON** | `--json r.json` | Pipelines, SIEM ingestion, custom analytics. Includes `risk_reasons` for every variant, and `otacon tui --from` reads it back for offline triage. |
| **Markdown** | `--md r.md` | Paste straight into Jira / GitHub issues / Slack |
| **HTML** | `--html r.html` | Hand to legal / compliance / management. Self-contained dark-theme file, zero JS (100% CSP-compliant pure-CSS filters, inline SVG risk distribution charts, defanged domain indicators, and urlscan sandbox links). |
| **CSV** | `--csv r.csv` | Spreadsheets — registered domains only, formula-injection-safe cells |

You can pass all export flags at once — every format is rendered from the same in-memory report, so they always agree.

### JSON structure (excerpt)

```json
{
  "target": "github.com",
  "started_at": "2026-06-08T14:23:01+00:00",
  "total_permutations": 143,
  "results": [
    {
      "domain": "githubupdate.com",
      "kind": "combosquat",
      "resolves": true,
      "has_mx": true,
      "has_ssl": true,
      "http_status": 200,
      "page_title": "GitHub - Security Update Required",
      "created_at": "2026-06-05T09:12:00+00:00",
      "age_days": 3,
      "risk_score": 92,
      "risk_level": "critical",
      "risk_reasons": [
        "technique: combosquat (+20)",
        "resolves to an IP (+10)",
        "has an MX record — ready for email phishing (+25)",
        "active SSL certificate (+15)",
        "responds HTTP 200 — active site (+15)",
        "registered 3 days ago (+20)"
      ],
      "is_likely_defensive": false
    }
  ]
}
```

Every score is fully decomposed — you can always answer *"why did this get 92?"*.

---

---

## Scan health

Every JSON report records how well the scan itself went, alongside the results:

| Field | Meaning |
|---|---|
| `dns_queries` | DNS lookups attempted during the scan — A, AAAA, MX, NS and TXT |
| `dns_failures` | Of those, how many failed rather than answering |
| `probe_failures` | Variants whose check raised an error instead of returning a result |
| `dnsbl_refused` | True when a reputation list declined to answer at all |
| `degraded` | True when DNS or probe failures reached 20% — a quiet result is not trustworthy |

A domain that does not exist is an *answer*, not a failure, so a healthy scan of
a typical target sits around 5% even though most variants are unregistered.

The distinction matters because "does not resolve" and "could not be checked"
produce the same empty result. When either failure count reaches 20% the
terminal stops reporting an all-clear and says the scan is inconclusive instead.

`dnsbl_refused` is its own flag because a refusal is not a clean bill of health.
Spamhaus declines queries that arrive through large public resolvers and answers
`127.255.255.254` rather than "not listed" — scored as clean, that silently
zeroed the heaviest single weight in the scoring. If you see it, scan from a
resolver of your own.

In a pipeline, `--fail-on` does this check for you: when nothing crossed the
threshold but the scan was degraded, a list refused, or a domain could not be
scanned, it exits **3** rather than 0. Without `--fail-on`, read `degraded` and
`dnsbl_refused` from the JSON yourself.

`degraded` is written for readers of the file; Otacon recomputes it from the
counters when it loads a report. Reports written before 2.2.0 carry none of
these fields and read back as zero/false.

## What the scan looked at

A report records which probes it ran, under `options`:

```json
"options": { "http": true, "whois": true, "dnsbl": true, "ct": false }
```

This is what makes two reports comparable. "No MX record" and "MX was never
checked" produce the same empty field, so `otacon diff` skips any signal the two
scans did not both gather and says so at the top of its output. The guided
mode's rescan reads the same field, so re-probing one row never queries a
registry or a blocklist the scan was told to leave alone.

Reports written before 4.0.0 have no `options` key and read back as a full
scan, which is how they were already compared.
