# Output formats

_[← back to the README](../README.md)_ · [Usage](USAGE.md) · [Scoring](SCORING.md) · [Output](OUTPUT.md) · [CI/CD](CI.md) · [FAQ](FAQ.md) · [Design](DESIGN.md)

---

One scan, five ways to consume it. Pick the one that fits your workflow:

| Format | Flag | Best for |
|---|---|---|
| **Terminal** | *(default)* | Reading the result now: a verdict card, the severity spread, one line per finding, and the reasons the top rows matter. `--top N` caps the table. |
| **JSON** | `--json r.json` | Pipelines, SIEM ingestion, custom analytics. Carries `risk_reasons` for every variant, and `otacon tui --from` reads it back for offline triage. |
| **Markdown** | `--markdown r.md` | Paste straight into Jira / GitHub issues / Slack |
| **HTML** | `--html r.html` | Hand to legal / compliance / management. Self-contained, zero JS (CSP-compliant pure-CSS filters, inline SVG distribution charts, defanged indicators, urlscan sandbox links) and rendered in the active `--theme`, so `daylight` is the one to print. |
| **CSV** | `--csv r.csv` | Spreadsheets — registered domains only, formula-injection-safe cells |

You can pass all export flags at once — every format is rendered from the same in-memory report, so they always agree. `--top` affects only what the terminal prints; the files always hold every variant.

### JSON structure (excerpt)

```json
{
  "target": "github.com",
  "started_at": "2026-10-29T14:23:01+00:00",
  "total_permutations": 143,
  "dns_hijack_detected": false,
  "dns_queries": 286,
  "dns_failures": 11,
  "cancelled": false,
  "results": [
    {
      "domain": "githubupdate.com",
      "kind": "combosquat",
      "note": "trust keyword: update",
      "resolves": true,
      "ip_addresses": ["203.0.113.17"],
      "has_mx": true,
      "has_ssl": true,
      "ssl_issuer": "R11",
      "http_status": 200,
      "page_title": "GitHub - Security Update Required",
      "title_similarity": 0.81,
      "has_login_form": true,
      "created_at": "2026-10-26T09:12:00+00:00",
      "age_days": 3,
      "dmarc_policy": null,
      "is_mail_spoofable": true,
      "risk_score": 92,
      "risk_level": "critical",
      "risk_reasons": [
        "technique: combosquat (+20)",
        "resolves to an IP (+10)",
        "has an MX record — ready for email phishing (+25)",
        "active SSL certificate (+15)",
        "responds HTTP 200 — active site (+15)",
        "infrastructure signals capped at +35 (raw +65 — a working website is not itself evidence of impersonation)",
        "cloned or highly similar page title to target (similarity: 0.81) (+25)",
        "login form detected — credential harvesting (+20)",
        "registered 3 days ago (+20)"
      ],
      "is_likely_defensive": false,
      "is_parked": false
    }
  ]
}
```

Abridged: each result carries 34 fields, including every DNS, TLS, mail and
reputation signal behind the score. Nothing is summarised away — the reason
list reproduces the arithmetic line by line, cap included, so you can always
answer *"why did this get 92?"*.

`cancelled` is `true` when the operator stopped the scan (`esc` in the
console) before it finished. A partial scan and a quiet one produce the same
short result list, so the fact travels with the report rather than reading as
an all-clear.

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

Reports written before 2.2.0 carry neither field and read back as zero, and
those written before 3.0.0 carry no `cancelled` field and read back as
`false`. Otherwise the format is unchanged.
