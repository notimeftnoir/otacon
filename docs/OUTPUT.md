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

Every JSON report carries two counters alongside the results:

| Field | Meaning |
|---|---|
| `dns_queries` | A and AAAA lookups attempted during the scan |
| `dns_failures` | Of those, how many failed rather than answering |

A domain that does not exist is an *answer*, not a failure, so a healthy scan of
a typical target sits around 5% even though most variants are unregistered.

The distinction matters because "does not resolve" and "could not be checked"
produce the same empty result. When failures reach 20% of lookups the terminal
verdict stops reporting an all-clear and says the scan is inconclusive instead.
In a pipeline, check the ratio yourself before trusting a quiet report:

```bash
otacon -q scan example.com --json report.json
python -c "
import json; r = json.load(open('report.json'))
assert r['dns_failures'] / max(r['dns_queries'], 1) < 0.2, 'scan degraded'"
```

Reports written before 2.2.0 carry neither field and read back as zero.
