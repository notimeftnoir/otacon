<p align="center">
  <img src="assets/brand/otacon-readme-header.png" alt="Otacon — domain impersonation detector" width="620">
</p>

<p align="center">
  <b>Domain impersonation detector</b> — finds typosquatting, homoglyph attacks and combosquatting aimed at your domain.
</p>

<p align="center">
  <a href="https://github.com/notimeftnoir/otacon/actions"><img src="https://github.com/notimeftnoir/otacon/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT">
</p>

---

**Domain impersonation detector** — finds typosquatting, homoglyph attacks and combosquatting aimed at your domain.

Otacon generates hundreds of realistic variants of a given domain (typos, visually identical characters, appended bait words, TLD swaps), checks **asynchronously** which of them are actively registered, and scores the threat level of each.

```
 ┌─────┐
 │  ◉  │  OTACON
 └─────┘  domain impersonation detector
          █ █ █ █ █ safe low med high crit
```

## Demo

```bash
asciinema play docs/demo.cast        # play locally (requires asciinema)
```

The cast shows a full scan of `github.com` — banner, progress bar, verdict summary, colored risk table with page-title fingerprints, and the footer.

## Why

Attackers register domains deceptively similar to real ones (`github-login.com`, `paypа1.com` with Cyrillic), host phishing on them and send emails. Otacon lets you **proactively** find such domains before they are used against you or your customers — useful during:

- reconnaissance in penetration tests (OSINT / threat modeling phase),
- brand-protection monitoring on a blue team,
- security audits before a launch.

## Otacon vs the alternatives

| Feature | **Otacon** | dnstwist | urlcrazy |
|---|:---:|:---:|:---:|
| Language | Python 3.10+ | Python | Ruby |
| DNS / A record check | ✓ | ✓ | ✓ |
| MX record (email-phishing signal) | ✓ | ✓ | ✓ |
| SSL certificate check | ✓ | ✓ | ✗ |
| HTTP probe + redirect detection | ✓ | ✓ | ✗ |
| **Domain age / WHOIS** (scoring signal) | **✓** | ✗ | ✗ |
| **Page-title fingerprint** (high/crit rows) | **✓** | ✗ | ✗ |
| **Transparent risk score** (0-100 + reasons) | **✓** | ✗ | ✗ |
| **11 permutation techniques** (incl. IDN, soundsquat, subdomain) | **✓** | partial | ✗ |
| **Live streaming table** (hits appear as detected) | **✓** | ✗ | ✗ |
| **Watch mode** — baseline diff (NEW/CHANGED/GONE) | **✓** | ✗ | ✗ |
| **CI/CD exit codes** (`--fail-on`) | **✓** | ✗ | ✗ |
| **Interactive post-scan actions** (open/WHOIS/rescan/allow) | **✓** | ✗ | ✗ |
| Concurrent async I/O | ✓ (~10 s) | threaded (~60 s) | sync (~45 s) |
| JSON export | ✓ | ✓ | ✓ |
| Markdown export | ✓ | ✗ | ✗ |
| **HTML report** (self-contained, dark palette) | **✓** | ✗ | ✗ |
| No paid APIs required | ✓ | ✓ | ✓ |

> Speed figures are approximate for a 150-variant scan on a broadband connection.
> dnstwist can also be run async with `--threads`; results vary.

## How it works

```
domain → permutation engine → async resolver → scoring → report
         (11 techniques)       (DNS/MX/SSL/HTTP)  (0-100)   (table/json/md/html)
```

### Variant generation techniques

| Technique | Example (`example.com`) | Description |
|---|---|---|
| **Homoglyph** | `exаmple.com` (Cyrillic а) | visually identical characters (Unicode + ASCII) |
| **IDN / Punycode** | `xn--exmple-cua.com` | ACE-encoded unicode homoglyphs |
| **Typo** | `exmple.com`, `examlpe.com` | typos: omission, duplication, swap, QWERTY adjacency |
| **Combosquat** | `example-login.com` | appended bait words (login, secure, verify...) |
| **TLD swap** | `example.net`, `example.io` | same name, different TLD |
| **Subdomain spoof** | `example.com.login.net` | real domain used as a label in a spoof registrar |
| **Bitsquat** | `dxample.com` | bit-flip (RAM/DNS memory errors) |
| **Hyphenation** | `ex-ample.com` | inserting/removing a hyphen |
| **Soundsquat** | `phishing.com` → `fishing.com` | phonetic substitution (ph/f, c/k, s/z…) |
| **Vowel swap** | `exomple.com` | replace each vowel with every other vowel |
| **Plural** | `examples.com` | plural/singular suffix variation |

### Risk signals

For each registered variant Otacon collects signals and sums them into a **0-100** score:

- **A record** — the domain resolves (someone is holding it),
- **MX record** — ready for email phishing *(strongest signal, +25)*,
- **SSL certificate** — active HTTPS infrastructure (+15),
- **HTTP 2xx** — content being served (+15),
- **HTTP 3xx** — redirect (+10),
- **HTTP 4xx/5xx** — registered but inactive (+5/+3),
- **Domain age** — freshly registered lookalikes are the strongest attack predictor:
  - `< 7 days` → **+20** (shown in red in the Age column)
  - `< 30 days` → **+12** (shown in red)
  - `< 90 days` → **+5**
  - `≥ 90 days` → no modifier; missing WHOIS data is never penalised,
- **permutation type** — homoglyphs are more dangerous than a distant combosquat.

The score maps to levels: `safe` → `low` → `medium` → `high` → `critical`.

Domains that redirect back to the original are flagged with **⚑** (likely defensive registration by the brand owner).

## Installation

### Recommended: pipx (isolated, globally available)

```bash
pipx install git+https://github.com/notimeftnoir/otacon.git
otacon
```

### Development install

Otacon requires **Python 3.10+**.

```bash
git clone https://github.com/notimeftnoir/otacon.git
cd otacon

python3 -m venv .venv
source .venv/bin/activate          # Linux / macOS
.venv\Scripts\activate             # Windows (PowerShell)
```

Then install — pick one:

```bash
# Editable install with dev extras (recommended)
pip install -e ".[dev]"

# Or from pinned requirements files
pip install -r requirements-dev.txt
```

```bash
otacon --version
```

> **Note (macOS / Kali):** the `aiodns` dependency needs the `c-ares` system library.
> Install with `brew install c-ares` (macOS) or `sudo apt install libc-ares-dev` (Debian/Kali).

## Usage

### Interactive mode (recommended)

Run `otacon` with no arguments to enter the interactive prompt — it guides you through domain input, mode selection and options:

```
› Enter your domain: example.com
› Mode: scan — DNS + HTTP, detects registered variants
› Network: DNS + HTTP (full, slower)
› Show unregistered variants? n  No
```

### Scan a domain (CLI)

```bash
otacon scan example.com
```

### Watch mode — continuous monitoring

`watch` scans, diffs against a saved baseline (`~/.otacon/<domain>.json`), and
shows only what **changed** since the last run (NEW / CHANGED / GONE).

```bash
# Single run — write baseline on first call, show only deltas on subsequent calls
otacon watch example.com

# Loop every 24 hours, exit cleanly with Ctrl+C
otacon watch example.com --interval 24h

# Notify a Slack/Teams webhook whenever a high/critical domain appears
otacon watch example.com --interval 1h --notify https://hooks.example.com/abc

# Save the diff as JSON
otacon watch example.com --json diff.json
```

First run reports all registered variants as **NEW** and writes the baseline.
Every subsequent run shows only what changed.

### Export reports

```bash
# JSON — full forensic data (IPs, MX records, scoring reasons)
otacon scan example.com --json report.json

# Markdown — ready to paste into a ticket/issue
otacon scan example.com --markdown report.md

# HTML — self-contained dark-palette report (open in browser, share as file)
otacon scan example.com --html report.html
```

### Options

```bash
otacon scan example.com --no-http          # DNS only (faster, disables ⚑ defensive flag)
otacon scan example.com -c 100             # more concurrent requests
otacon scan example.com --all              # show unregistered variants too
```

### CI/CD exit codes

Use `--fail-on` to gate a pipeline — Otacon exits **2** when any registered
variant reaches the specified risk level or higher:

```bash
# Exit 2 if any critical lookalike is found (strict — only top threats)
otacon scan example.com --fail-on critical

# Exit 2 if any high-or-above risk domain is registered (recommended)
otacon scan example.com --fail-on high

# Exit 2 on anything registered at medium or above
otacon scan example.com --fail-on medium
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Clean — no variant at or above the threshold |
| `1` | Runtime error (invalid domain, unreadable file, etc.) |
| `2` | Threshold breached — at least one result `>= --fail-on` level |

Combine with `--exclude` / `--exclude-file` to whitelist known-good aliases
so they don't trigger the threshold.

### Whitelist — skipping known-good domains

Some variants are **legitimate** domains of the owner (e.g. `googlemail.com` belongs to Google). You can exclude them so they don't clutter the report — excluded domains are not even checked over the network.

```bash
# comma-separated
otacon scan google.com --exclude "googlemail.com,googleaccount.com"

# from a file (one domain per line, '#' = comment)
otacon scan google.com --exclude-file whitelist.txt
```

### Offline mode — just preview the variants

```bash
otacon generate example.com                # no network checks
otacon generate example.com --limit 20
```

## Example output

```
⚠ 3 registered · crit: 1 · mx: 1 · fresh <7d: 1

Otacon · target: github.com
┌──────────────────────────────────────────────┬────────────────────┬──────────┬─────────┬─────────┬────────┬──────────┐
│ Domain                                       │ Risk               │      Age │   DNS   │   MX    │  SSL   │  HTTP    │
├──────────────────────────────────────────────┼────────────────────┼──────────┼─────────┼─────────┼────────┼──────────┤
│ githubupdate.com                             │ ███████░  92       │       3d │    ✓    │    ✓    │   ✓    │  200     │
│ combosquat                                   │                    │          │         │         │        │          │
│ "GitHub - Security Update Required"          │                    │          │         │         │        │          │
│ bithub.com                                   │ █████░░░  68       │       2y │    ✓    │    —    │   ✓    │  301     │
│ typo                                         │                    │          │         │         │        │          │
│ githuub.com                                  │ ████░░░░  48       │      8mo │    ✓    │    —    │   —    │  404     │
│ typo                                         │                    │          │         │         │        │          │
└──────────────────────────────────────────────┴────────────────────┴──────────┴─────────┴─────────┴────────┴──────────┘
Permutations: 143 · registered: 3 · med: 1 · high: 1 · crit: 1
```

- **Verdict banner** (`⚠ 3 registered…`) appears above the table — red when criticals exist, green "✓ clean" when none.
- **Age column** is red for domains registered within 30 days — the strongest phishing predictor.
- **Page title** shown as a third line for `high`/`critical` rows (e.g. `"GitHub - Security Update Required"`).
- **⚑** marks domains that redirect back to the original — likely defensive registrations.

## Interpreting results

**Otacon flags candidates, it does not pass verdicts.** A high score means a
domain technically *matches the profile* of a fake (registered, has MX, SSL, a
live service) — but the final judgment belongs to the analyst.

Common cases that need manual verification:

- **Legitimate owner domains** — e.g. `googlemail.com` is a real Google domain
  despite a `critical` score. These are often flagged with ⚑ (redirect to original).
  Exclude them via `--exclude` / `--exclude-file`.
- **Parked / for-sale domains** — often have MX and SSL but run no active
  phishing. Still worth monitoring (they can be weaponized later).
- **Defensive registrations** — the brand owner bought the variants preemptively.
  Look for the ⚑ indicator.

Practical workflow: sort by risk → filter out known-good domains with a
whitelist → manually verify `critical`/`high` (open in a sandbox, inspect the
content, compare the registrar and registration date in WHOIS). Automation
narrows the field from hundreds of variants down to a dozen real candidates —
a human does the rest.

## Architecture

```
otacon/
├── permutations.py   # variant generation engine (11 techniques)
├── resolver.py       # async DNS/MX/SSL/HTTP + page-title parsing (semaphore + pooling)
├── whois.py          # async WHOIS lookup — domain age scoring signal
├── scoring.py        # transparent rule-based risk engine (0-100, with reasons)
├── reporters.py      # table / json / markdown + verdict banner + risk bar
├── state.py          # baseline persistence for watch mode (~/.otacon/<domain>.json)
├── watch.py          # diff engine + watch-mode loop (NEW/CHANGED/GONE)
├── models.py         # Pydantic models (type safety + JSON serialization)
├── theme.py          # Watcher mark banner + color palette (single source of truth)
├── interactive.py    # interactive prompt + post-scan action loop
└── cli.py            # Typer + Rich entrypoint (scan / watch / generate)
```

Design decisions:

- **async-first** — hundreds of domains checked concurrently (seconds instead
  of minutes), bounded by a semaphore so the DNS resolver isn't flooded.
- **transparent scoring** — rules instead of ML; the user sees WHY something
  got its score (the `risk_reasons` field in JSON export).
- **layer separation** — generation / checking / scoring / output are
  independent and individually testable.
- **no paid APIs** — works right after installation.

## Testing

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## Ethics and scope

Otacon is a **defensive and reconnaissance** tool. It performs only passive
queries (DNS, TLS handshake, a single HTTP GET) — it does not attack, scan
aggressively, or attempt exploitation. Use it to protect your own domains and
within authorized security testing.

## License

MIT
