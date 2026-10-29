# Usage

_[← back to the README](../README.md)_ · [Usage](USAGE.md) · [Scoring](SCORING.md) · [Output](OUTPUT.md) · [CI/CD](CI.md) · [FAQ](FAQ.md) · [Design](DESIGN.md)

---

## The five subcommands

Run Otacon with no subcommand for the triage console — that is the surface the
tool is built around.

| Mode | Network? | Use when |
|---|---|---|
| *(no subcommand)* | yes | **The triage console.** Name a target, pick how deep to look, and the scan runs inside it. Needs an interactive terminal; elsewhere it tells you to use `otacon scan`. |
| `scan` | yes | One-shot audit that prints a verdict and writes reports. What you put in CI. |
| `tui` | yes, or none with `--from` | The console on a target you already know, or on a report already on disk. |
| `generate` | **no** | Offline wordlist generation — feed `subfinder`, `nuclei`, `ffuf`, or sanity-check what Otacon *would* check. |
| `diff` | **no** | Compare two saved JSON reports. |
| `watch` | **no** | Keep the list of targets worth re-scanning, and print the crontab lines for them. |

---

## Common invocations

```bash
otacon                                        # the triage console
otacon scan example.com                       # one-shot scan, all signals
otacon scan example.com --no-http             # DNS only — faster, fewer signals
otacon scan example.com --top 10              # table capped at the riskiest rows
otacon scan example.com --all                 # include unregistered variants
otacon scan example.com --concurrency 100     # crank concurrency (default 50)
otacon scan example.com --exclude "alias.com,brand.io"
otacon scan example.com --exclude-file allowed.txt
otacon scan example.com --json r.json --html r.html --markdown r.md --csv r.csv
otacon scan example.com --fail-on high        # CI gate — exit 2 on high/critical
otacon scan example.com --weights-file weights.json  # custom scoring weights

# Several targets, scanned in sequence
otacon scan github.com google.com example.com
otacon scan --domains-file brands.txt         # one domain per line, # = comment
otacon scan mycompany.com --domains-file more_brands.txt
otacon scan --domains-file brands.txt --html report.html   # aggregated report
otacon scan --domains-file brands.txt --fail-on critical   # gate the whole set

otacon tui example.com                        # scan, then triage it
otacon tui --from report.json                 # reopen a report, no network
otacon generate example.com -o variants.txt   # wordlist only, no network
otacon diff old.json new.json                 # what changed between two scans
otacon watch --add example.com                # watchlist + crontab lines

otacon --debug scan example.com               # global flags precede the subcommand
otacon --theme daylight scan example.com      # light terminal
otacon --version
```

---

## Flags

> **Placement matters.** `--quiet`, `--debug`, `--theme`, `--ascii` and
> `--version` belong to `otacon` itself and come **before** the subcommand
> (`otacon --debug scan example.com`). Everything else comes **after** it
> (`otacon scan example.com --fail-on high`).

### Global options

| Flag | Default | Description |
|---|---|---|
| `--debug`, `-v`, `--verbose` | off | Log DNS/WHOIS/HTTP graceful-degradation events to stderr. |
| `--quiet`, `-q` | off | Disable UI, banner and progress; print JSON to stdout. |
| `--theme` | `midnight` | `midnight` · `daylight` · `vision` · `mono`. Also settable with `OTACON_THEME`; `NO_COLOR` resolves to `mono`. |
| `--ascii` | off | ASCII stand-ins for every block, arrow and box-drawing glyph. Also `OTACON_ASCII=1`. |
| `-V`, `--version` | — | Print version and exit. |

`--quiet` and `--debug` combine:
`otacon -q -v scan example.com > report.json 2> debug.log` keeps stdout clean
JSON and puts every degradation event in the log.

### `scan`

| Flag | Default | Description |
|---|---|---|
| `--domains-file`, `-D` | — | File with one domain per line (`#` = comment) — many targets in one run. |
| `--json` | — | Write the full report (every variant, every signal, every reason) to a file. |
| `--markdown` / `--md` | — | Write a Markdown table ready to paste into a ticket. |
| `--html` | — | Write a self-contained HTML report, themed like the terminal. |
| `--csv` | — | Write a CSV of registered domains (spreadsheet-safe, CWE-1236 hardened). |
| `--no-http` | off | Skip HTTP & TLS probing. DNS+MX+WHOIS only. Disables the defensive flag. |
| `--no-whois` | off | Skip WHOIS / RDAP age lookups — faster, and avoids registry rate limits. |
| `--no-dnsbl` | off | Skip the passive Spamhaus DBL / SURBL reputation lookups. |
| `--no-ct` | off | Skip Certificate Transparency discovery. |
| `-c`, `--concurrency` | `50` | Max concurrent DNS/HTTP checks. Raise carefully — your resolver may rate-limit. |
| `--all` | off | Show unregistered variants in the output too. |
| `-n`, `--top` | `0` (all) | Print only the N riskiest rows; the rest are counted, not listed. Reports are unaffected. |
| `-x`, `--exclude` | — | Comma-separated allow-list: `--exclude "alias.com,brand.io"` |
| `--exclude-file` | — | Path to a file with one domain per line. `#` starts a comment. |
| `--fail-on` | — | `low` / `medium` / `high` / `critical` — exit `2` when any registered variant reaches this level. |
| `-w`, `--weights-file` | — | JSON file overriding default scoring weights (below). |

<details>
<summary><b>Custom scoring weights (<code>--weights-file</code>)</b></summary>

Override any subset of the default point values without touching
`scoring/config.py`. Unspecified keys keep their default:

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

### `tui`

| Flag | Default | Description |
|---|---|---|
| `[domain]` | — | Scan this target, then open the console on the result. |
| `--from` | — | Triage a saved JSON report instead of scanning. No network at all. |
| `-c`, `--concurrency` | `50` | Concurrent checks, as for `scan`. |
| `--no-http` / `--no-whois` / `--no-dnsbl` / `--no-ct` | off | Skip that group of checks, as for `scan`. |

`tui` needs exactly one of the two: bare `otacon tui` is an error, because
plain `otacon` is already the way to reach the start screen.

### `generate`

| Flag | Default | Description |
|---|---|---|
| `-n`, `--limit` | `0` (all) | Print only the first N variants. The file written by `--output` always contains every variant. |
| `-o`, `--output` | — | Write the variants, one per line, to a file. |
| `-x`, `--exclude` | — | Comma-separated allow-list, same syntax as `scan`. |
| `--exclude-file` | — | Path to an allow-list file, one domain per line. |

### `diff`

```bash
otacon diff earlier.json later.json
```

| Flag | Default | Description |
|---|---|---|
| `--json` | — | Write the diff to a file as JSON. |
| `--fail-on-threats` | off | Exit `2` when the newer report has new high or critical findings. |

### `watch`

| Flag | Default | Description |
|---|---|---|
| `-a`, `--add` | — | Put a target on the watchlist. |
| `-r`, `--remove` | — | Take one off it. |
| `--schedule` | `17 7 * * *` | The cron schedule in the printed lines. |

With no flags it lists the watchlist and prints a ready-to-paste crontab line
per target. Otacon never becomes a daemon — the machine already has one.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — nothing at or above the `--fail-on` threshold |
| `1` | Runtime error (bad input, empty domain, file I/O error) |
| `2` | Threshold breached — at least one registered variant met `--fail-on` |

---

## Triage console

```bash
otacon                            # start screen: pick a target and a depth
otacon tui example.com            # scan, then open the console on the result
otacon tui example.com --no-whois # same, skipping registry lookups
otacon tui --from report.json     # reopen a saved report, no network at all
```

A report opens on the **overview**: the verdict in plain words, how the
findings split across severities, what moved since the last scan of this
target, and the three rows worth opening first with their reasons. `enter`
goes on to the table.

In the table, the **dossier is on the left** and the **findings on the right**.
The dossier tracks the cursor — each signal with a one-line explanation of what
it means, then the full scoring breakdown — and both panes update as you move.
A persistent status bar carries the active filter, the row count, the marks and
the order.

| Key | Action |
|---|---|
| `↑` `↓` or `k` `j` | Move between rows |
| `enter` | From the overview, open the full table |
| `1` … `5` | Show one severity only — critical, high, medium, low, safe. The same key lifts it. |
| `0` | Show every severity |
| `/` | Filter by part of a domain name. `esc` clears it. |
| `u` | Also show variants nobody has registered (hidden by default) |
| `s` | Change the order: risk, name, age, technique |
| `f` | Dim every row below the worst band present |
| `b` | Swap the severity glyph for the full bar |
| `space` | Mark this row and move on |
| `v` | Mark everything the filter shows, or clear the marks |
| `o` | Open the selected site — warns before it does |
| `w` | Look up when the domain was registered (WHOIS / RDAP) |
| `r` | Re-check the selected row now |
| `t` | Write abuse takedown notices for the marked rows |
| `e` | Export the marked rows as JSON |
| `x` | Export every row the current filter shows |
| `a` | Wave the marked rows through, now and in future scans of this target |
| `c` | What changed since the previous stored scan of this target |
| `,` | Settings, the allow-list and the watchlist |
| `?` | Glossary: every key, score band, flag and technique in one sentence each |
| `esc` | Close the help or the filter; from a screen, go back |
| `q` | Quit |

**Keys that act on a row act on every marked row instead, once anything is
marked.** Bulk writes arm and confirm with the count first, marks are held by
domain rather than by row index, and an action only ever touches rows the
filter currently shows.

`--from` makes the console a reader for anything already on disk, so a nightly
`otacon -q scan` in CI can write a report that is triaged by hand the next
morning without touching the network again.

Filenames written by `t`, `e` and `x` are derived from the scanned domain,
which is attacker-influenced, so they go through the same containment check as
the CLI's `--json` and `--html` paths. A name that would escape the working
directory is refused rather than written.

### Scanning inside the console

The start screen takes the target and one of three presets:

| Preset | What it checks |
|---|---|
| **Quick** | Names only — about ten seconds |
| **Standard** | Also websites and reputation |
| **Thorough** | Everything, plus registration dates *(selected on open)* |

The four protocol-named switches (`HTTP`, `WHOIS`, `DNSBL`, `CT`) sit behind an
*Advanced* disclosure for anything the presets do not cover. Thorough is
selected on open, so a preset can never quietly make a scan less thorough than
it would have been.

While the scan runs you see the stage it is in, the running tally, and findings
appearing as they are scored. **`esc` stops a scan and keeps what it found** —
the report is marked `cancelled` and the verdict says so rather than reading as
an all-clear.

`ctrl+p` opens the command palette, which lists Otacon's own commands
alongside Textual's.

---

## What Otacon remembers

Two directories under the same root, both plain JSON, both owner-only — a scan
reveals which brand you watch and which lookalikes are live.

```
<OTACON_HOME>/<target>/<timestamp>.json      every scan
<OTACON_HOME>/config/settings.json           theme, ascii, preset, fail-on
<OTACON_HOME>/config/targets/<domain>.json   allow-list and watchlist
```

| Variable | Effect |
|---|---|
| `OTACON_HOME` | The root. Defaults to `$XDG_DATA_HOME/otacon`, or `~/.otacon`. |
| `XDG_DATA_HOME` | Used when `OTACON_HOME` is unset; scans land in `$XDG_DATA_HOME/otacon`. |
| `OTACON_NO_HISTORY=1` | Keep no scans |
| `OTACON_NO_CONFIG=1` | Keep no settings, allow-list or watchlist |

**Scan history** is one report per scan, in the format `--json` writes. No
database and no index — a directory you can read, grep, copy and delete. The 30
most recent scans per target are kept and older ones dropped, so it stays a few
megabytes without anyone having to think about it. It is what lets the console
list what you looked at before, reopen it offline, and show what changed.

**Config** is the other half: what the operator decided rather than what a scan
found. Nothing here raises on bad input — a hand-edited file or a theme name
that no longer exists falls back to the default rather than costing somebody a
scan.

---

## Allow-lists and the defensive flag

Brands often own their own lookalikes defensively — `google.com` owns
`gooogle.com` and redirects it. Otacon flags those: a variant that redirects to
the original and has no MX is marked **defensive** and scored zero.

Flagging is not the same as forgetting. There are three ways to leave a domain
out of a scan:

| How | Scope |
|---|---|
| `a` in the console | Permanent, per target. Stored in `<OTACON_HOME>/config/targets/<domain>.json`, and applied to every future scan of that target. |
| `--exclude "a.com,b.com"` | This run |
| `--exclude-file list.txt` | This run |

An allow-list file is one domain per line, `#` starting a comment:

```text
# defensive registrations, owned by us
gooogle.com
goggle.com
g00gle.com
```

Excluded domains are skipped before any network call, saving time and quota.
`otacon watch` shows how many each target has, and `,` in the console opens the
list to edit.

---

## Terminal output

Every scan ends with a **verdict card**: a plain-language headline, a bar
showing how the registered lookalikes split across severities, and the raw
counts. The table that follows is **one line per finding**, and the reasons the
top rows matter are spelled out underneath it at the full width of the
terminal. A short *Next steps* list suggests the follow-up commands that fit
the result. `-q` silences all of it along with the rest of the UI.

A scan whose resolver is failing produces the same empty result as a clean one,
so Otacon counts its DNS lookups: once failures reach 20% the verdict reports
the scan as **inconclusive** instead of an all-clear. See
[`OUTPUT.md`](OUTPUT.md#scan-health) for the counters and how to check them in
a pipeline.

The bare `otacon` command opens with a short animation: the wordmark decodes
out of lookalike characters. It only plays in an interactive colour terminal —
pipes, CI (`CI` set), `NO_COLOR` and `OTACON_NO_ANIMATION=1` get the static
banner.

---

## Reading a report

The [technique table in the README](../README.md#what-it-looks-for) lists real
generator output, not illustrations. Two details worth knowing:

- **Unicode lookalikes are emitted as punycode.** Swapping the `l` in
  `example.com` for a Polish `ł` is reported as `xn--exampe-7db.com`, because
  that is the name DNS actually resolves and the form you will see in logs.
  Those land under **IDN**, which leaves the **Homoglyph** rows for the ASCII
  confusables (`1`/`l`, `4`/`a`, `rn`/`m`).
- **Each variant is reported once, under the first technique that produced
  it.** Techniques overlap, and the priority order is the one in that table.
  That is why `examples.com` is labelled a typo rather than a plural for a
  target like `example.com`: `s` sits next to `e` on QWERTY, so the typo
  generator reaches it first. On `shop.com`, where no adjacent key produces it,
  `shops.com` comes through as a plural.

Certificate Transparency findings are reported as `ct-log` rather than as a
technique, and subdomains of your own domain are dropped before scoring.

The generator deduplicates results and **never includes the original domain**.
