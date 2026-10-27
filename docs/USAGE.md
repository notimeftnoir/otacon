# Usage

_[← back to the README](../README.md)_ · [Usage](USAGE.md) · [Scoring](SCORING.md) · [Output](OUTPUT.md) · [CI/CD](CI.md) · [FAQ](FAQ.md) · [Design](DESIGN.md)

---

```bash
otacon                                        # interactive mode (guided prompts)
otacon scan example.com                       # one-shot scan, all signals
otacon scan example.com --no-http             # DNS only — faster, fewer signals
otacon scan example.com --all                 # include unregistered variants
otacon scan example.com --concurrency 100     # crank concurrency (default 50)
otacon scan example.com --resolver 1.1.1.1    # bypass a router DNS that drops queries
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

The two combine: `otacon -q -v scan example.com > report.json 2> debug.log` keeps
the JSON on stdout clean and puts every degradation event in `debug.log`.

**`scan` options** (after `otacon scan`):

| Flag | Default | Description |
|---|---|---|
| `--no-http` | off | Skip HTTP & TLS probing. DNS+MX+WHOIS only. Disables the `»` defensive flag. |
| `--all` | off | Show unregistered variants in the output. |
| `-c`, `--concurrency` | `50` | Max concurrent DNS/HTTP checks. Raise carefully — your resolver may rate-limit. |
| `-r`, `--resolver` | system | DNS server IP to query instead of the system resolver; repeatable. Home-router DNS proxies often drop bursts of queries, which shows up as *inconclusive* variants; `--resolver 1.1.1.1` fixes that. |
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
  [*] [o]pen      — preview URL & sandbox link, prompt before opening
      [w]hois     — show registration info (via RDAP / WHOIS)
      [t]akedown  — generate abuse / phishing takedown notice
      [e]xport    — save result as JSON
      [a]llow     — skip in this session
      [r]escan    — re-check this domain now
      [b]ack      — pick a different domain
      [q]uit      — exit actions
```

Designed for triaging a fresh scan without leaving the terminal: safely inspect lookalike sites via urlscan sandbox links, retrieve RDAP/WHOIS details, draft abuse takedown notices with embedded technical evidence, or allow-list defensive domains.

Picking a domain first shows its **dossier**: every signal Otacon found, each with a one-line explanation of what it means (for example *Mail: mx.lookalike.com, can send email that looks like it is from you*).

---

## Terminal output

Every scan ends with a **verdict card**: a plain-language headline, a bar showing how the registered lookalikes split across risk levels, and the raw counts. Below it, each row of the table lists the domain's two strongest reasons. A short *Next steps* list suggests the follow-up commands that fit the result; `-q` silences it along with the rest of the UI.

The bare `otacon` command opens with a short animation: the wordmark decodes out of lookalike characters. It only plays in an interactive colour terminal. Pipes, CI (`CI` set), `NO_COLOR` and `OTACON_NO_ANIMATION=1` get the static banner instead.

---

## Threat intel and Certificate Transparency

Every scan also asks three outside sources what they already know. `--no-intel` turns all of them off.

| Source | What it adds | Leaves your machine |
|---|---|---|
| OpenPhish + Phishing Army feeds | A variant listed as phishing scores +40; listed hosts carrying your brand (`allegro.id-23843.click`) go to `discovered` | nothing: both feeds are downloaded whole and matched locally, cached 6 h |
| crt.sh (Certificate Transparency) | Certificates issued in the last 30 days for names carrying your brand, also in `discovered` | your brand word |
| URLhaus | A registered variant on record scores +40 | each registered variant's name; only runs when `ABUSECH_AUTH_KEY` is set |

Most real phishing hangs the brand off a throwaway domain that no permutation produces, which is why `discovered` exists: those hosts are reported, never probed. crt.sh is often slow or down; it runs alongside the scan, and when it cannot be reached the report says so instead of showing zero. Your own other domains (`allegrogroup.com`) belong in the whitelist, which also hides them and their subdomains from `discovered`.

---

## Monitoring (`otacon watch`)

`watch` scans once, compares with the previous run and reports only what changed, so it belongs in a scheduler rather than a terminal:

```text
NEW         examp1e.com      registered, risk 90
ESCALATED   exampel.com      mail server added, website went live (risk 85)
GONE        exmple.com       no longer registered or reachable
DISCOVERED  allegro.id-23843.click   seen in Phishing Army
```

- The first run records a baseline and alerts nothing.
- Probes flap: a TLS handshake or HTTP request to a slow host fails in some runs and not others. A certificate, website, mail server or SPF record therefore escalates only once it is seen in two runs in a row, and is remembered from then on; a DNS answer or a feed listing escalates at once. A variant must be missing two runs in a row to count as gone, and one DNS never answered is never gone.
- `--webhook URL` (repeatable) or the `OTACON_WEBHOOK` variable: Slack, Discord and Teams URLs get their native message shape, anything else the JSON events. Domains in messages are defanged (`exampel[.]com`) so chat apps do not turn them into clickable links.
- `--exit-code` exits 2 when something changed; `-q` prints the events as JSON.
- State lives in `%LOCALAPPDATA%\otacon\watch.sqlite` (Windows) or `~/.local/share/otacon/watch.sqlite`; `--state PATH` overrides it.

**cron** (every 6 hours):

```cron
0 */6 * * * OTACON_WEBHOOK=https://hooks.slack.com/services/... otacon watch example.com --resolver 1.1.1.1
```

**Windows Task Scheduler:**

```powershell
schtasks /Create /TN "Otacon watch" /SC HOURLY /MO 6 /TR "otacon watch example.com --resolver 1.1.1.1"
```

**GitHub Actions** (the repository ships an action; the state is kept in the Actions cache):

```yaml
on:
  schedule: [{cron: "0 */6 * * *"}]
jobs:
  watch:
    runs-on: ubuntu-latest
    steps:
      - uses: notimeftnoir/otacon@<release-tag>
        with:
          domains: example.com example.pl
          webhook: ${{ secrets.OTACON_WEBHOOK }}
```

---

## Whitelist / defensive flag

Brands often own their own lookalikes defensively (e.g., `google.com` owns `gooogle.com` and redirects it). Otacon flags these with `»` when the redirect points back to the original:

```text
microsft.com    » microsoft.com    crit(85) — but defensive
```

After the scan, Otacon offers to write all `»`-flagged domains to `whitelist.txt`. Future runs in the same directory pick this file up automatically; you can also point at a custom file with `--exclude-file path/to/list.txt`.

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
