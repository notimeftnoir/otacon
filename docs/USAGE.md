# Usage

_[← back to the README](../README.md)_ · [Usage](USAGE.md) · [Scoring](SCORING.md) · [Output](OUTPUT.md) · [CI/CD](CI.md) · [FAQ](FAQ.md) · [Design](DESIGN.md)

---

```bash
otacon                                        # interactive mode (guided prompts)
otacon scan example.com                       # one-shot scan, all signals
otacon scan example.com --no-http             # DNS only — faster, fewer signals
otacon scan example.com --all                 # include unregistered variants
otacon scan example.com --concurrency 100     # crank concurrency (default 50)
otacon scan example.com --exclude "alias.com,brand.io"
otacon scan example.com --exclude-file allowed.txt
otacon scan example.com --json r.json --html r.html --markdown r.md --csv r.csv
otacon scan example.com --fail-on high        # CI gate — exit 2 on high/critical
otacon scan example.com --weights-file weights.json  # custom scoring weights

# Scan multiple domains (sequential)
otacon scan github.com google.com example.com

# Scan from a file (one domain per line, # = comment)
otacon scan --domains-file brands.txt

# Combine: extra domains alongside a file
otacon scan mycompany.com --domains-file more_brands.txt

# Aggregated HTML report for all domains
otacon scan github.com google.com --html report.html

# Aggregated JSON export
otacon scan --domains-file brands.txt --json results.json

# Fail CI if any domain has a critical hit
otacon scan --domains-file brands.txt --fail-on critical

otacon generate example.com -o variants.txt   # wordlist only, no network
otacon --debug scan example.com               # global flags precede the subcommand
otacon --version                              # print version and exit
```

### CLI flags reference

> **Placement matters:** `--debug`/`--quiet`/`--version` belong to `otacon` itself and must come
> **before** the subcommand (`otacon --debug scan example.com`). Every other flag below belongs to
> `scan` and comes **after** it (`otacon scan example.com --fail-on high`).

**Global options** (before the subcommand):

| Flag | Default | Description |
|---|---|---|
| `--debug`, `-v`, `--verbose` | off | Log DNS/WHOIS/HTTP graceful-degradation events to stderr. |
| `--quiet`, `-q` | off | Disable UI/banner/progress; print JSON to stdout. |
| `-V`, `--version` | — | Print version and exit. |

**`scan` options** (after `otacon scan`):

| Flag | Default | Description |
|---|---|---|
| `--no-http` | off | Skip HTTP & TLS probing. DNS+MX+WHOIS only. Disables the ⚑ defensive flag. |
| `--all` | off | Show unregistered variants in the output. |
| `-c`, `--concurrency` | `50` | Max concurrent DNS/HTTP checks. Raise carefully — your resolver may rate-limit. |
| `-x`, `--exclude` | — | Comma-separated whitelist: `--exclude "alias.com,brand.io"` |
| `--exclude-file` | — | Path to a file with one domain per line. `#` starts a comment. |
| `--domains-file`, `-D` | — | File with one domain per line (`#` = comment) — scan many targets in one run. |
| `--json` | — | Write the full report (every variant, every signal, every reason) to a file. |
| `--markdown` / `--md` | — | Write a Markdown table ready to paste into a ticket. |
| `--html` | — | Write a self-contained dark-theme HTML report. |
| `--csv` | — | Write a CSV report of registered domains (spreadsheet-safe, CWE-1236 hardened). |
| `--fail-on` | — | `low` / `medium` / `high` / `critical` — exit `2` when any registered variant reaches this level. |
| `-w`, `--weights-file` | — | Path to a JSON file overriding default scoring weights (see below). |

<details>
<summary><b>Custom scoring weights (<code>--weights-file</code>)</b></summary>

Override any subset of the default point values without touching `scoring.py`. Unspecified keys keep their default:

```json
{
  "points_mx": 30,
  "points_ssl_fresh": 15,
  "kind_base": { "homoglyph": 30 }
}
```

```bash
otacon scan example.com --weights-file weights.json
```

</details>

**`generate` options** (after `otacon generate`):

| Flag | Default | Description |
|---|---|---|
| `-n`, `--limit` | `0` (all) | Print only the first N variants. The file written by `--output` always contains every variant. |
| `-o`, `--output` | — | Write the variants, one per line, to a file — a wordlist for `subfinder`, `nuclei`, `ffuf`, etc. |
| `-x`, `--exclude` | — | Comma-separated whitelist, same syntax as `scan`. |
| `--exclude-file` | — | Path to a whitelist file, one domain per line. |

### Exit codes (for CI gating)

| Code | Meaning |
|---|---|
| `0` | Clean — nothing at/above the `--fail-on` threshold |
| `1` | Runtime error (bad input, empty domain, file I/O error) |
| `2` | Threshold breached — at least one registered variant met `--fail-on` |

---

---

## Modes

Otacon has two subcommands plus an interactive guided mode:

| Mode | Network? | Use when |
|---|---|---|
| `scan` | yes | One-shot audit. Most common. |
| `generate` | **no** | Offline wordlist generation. Useful for feeding into external tooling (`subfinder`, `nuclei`, etc.) or sanity-checking what Otacon *would* check. |
| *(no subcommand)* | yes | **Interactive mode** — guided prompts, then a post-scan action loop (open in browser, WHOIS, rescan, allow-list). |

---

---

## Interactive mode

Run `otacon` with no subcommand for a guided experience. After the scan, you can act on each registered domain individually:

```text
Action for githubupdate.com:
  [*] [o]pen   — open in browser
      [w]hois  — show registration info
      [e]xport — save result as JSON
      [a]llow  — skip in this session
      [r]escan — re-check this domain now
      [b]ack   — pick a different domain
      [q]uit   — exit actions
```

Designed for triaging a fresh scan without leaving the terminal: open the suspicious site, check WHOIS, decide to allow-list or escalate.

---

---

## Whitelist / defensive flag

Brands often own their own lookalikes defensively (e.g., `google.com` owns `gooogle.com` and redirects it). Otacon flags these with ⚑ when the redirect points back to the original:

```text
microsft.com    ⚑ → microsoft.com    crit(85) — but defensive
```

After the scan, Otacon offers to write all ⚑-flagged domains to `whitelist.txt`. Future runs in the same directory pick this file up automatically; you can also point at a custom file with `--exclude-file path/to/list.txt`.

Whitelist file format:

```text
# defensive registrations, owned by us
gooogle.com
goggle.com
g00gle.com
```

Whitelisted domains are skipped before any network call — saving both time and quota.

---

---

## Reading a report

The [technique table in the README](../README.md#detection-techniques) lists
real generator output, not illustrations. Two details worth knowing before
you read a report:

- **Unicode look-alikes are emitted as punycode.** Swapping the `l` in
  `example.com` for a Polish `ł` is reported as `xn--exampe-7db.com`, because
  that is the name DNS actually resolves and the form you will see in logs.
  Those land under **IDN**, which leaves the **Homoglyph** rows for the ASCII
  confusables (`1`/`l`, `4`/`a`, `rn`/`m`).
- **Each variant is reported once, under the first technique that produced it.**
  Techniques overlap, and the priority order is the one in that table. That is
  why `examples.com` is labelled a typo rather than a plural for a target like
  `example.com`: `s` sits next to `e` on QWERTY, so the typo generator reaches
  it first. On `shop.com`, where no adjacent key produces it, `shops.com`
  comes through as a plural.

The generator deduplicates results and **never includes the original domain** in the output.
