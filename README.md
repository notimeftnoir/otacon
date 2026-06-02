# Otacon

**Domain impersonation detector** — finds typosquatting, homoglyph attacks and combosquatting aimed at your domain.

Otacon generates hundreds of realistic variants of a given domain (typos, visually identical characters, appended bait words, TLD swaps), checks **asynchronously** which of them are actively registered, and scores the threat level of each.

```
 ┌─◎─┐  OTACON
 └───┘  domain impersonation detector
       █████ safe low med high crit
```

## Why

Attackers register domains deceptively similar to real ones (`github-login.com`, `paypа1.com` with Cyrillic), host phishing on them and send emails. Otacon lets you **proactively** find such domains before they are used against you or your customers — useful during:

- reconnaissance in penetration tests (OSINT / threat modeling phase),
- brand-protection monitoring on a blue team,
- security audits before a launch.

## How it works

```
domain → permutation engine → async resolver → scoring → report
         (6 techniques)        (DNS/MX/SSL/HTTP)  (0-100)   (table/json/md)
```

### Variant generation techniques

| Technique | Example (`example.com`) | Description |
|---|---|---|
| **Homoglyph** | `exаmple.com` (Cyrillic а) | visually identical characters (Unicode + ASCII) |
| **Typo** | `exmple.com`, `examlpe.com` | typos: omission, duplication, swap, QWERTY adjacency |
| **Combosquat** | `example-login.com` | appended bait words (login, secure, verify...) |
| **TLD swap** | `example.net`, `example.io` | same name, different TLD |
| **Bitsquat** | `dxample.com` | bit-flip (RAM/DNS memory errors) |
| **Hyphenation** | `ex-ample.com` | inserting/removing a hyphen |

### Risk signals

For each registered variant Otacon collects signals and sums them into a **0-100** score:

- **A record** — the domain resolves (someone is holding it),
- **MX record** — ready for email phishing *(strongest signal)*,
- **SSL certificate** — active HTTPS infrastructure,
- **HTTP response** — content being served,
- **permutation type** — homoglyphs are more dangerous than a distant combosquat.

The score maps to levels: `safe` → `low` → `medium` → `high` → `critical`.

## Installation

Otacon requires **Python 3.10+**. Installation in a virtual environment is recommended — it isolates dependencies and avoids the `externally-managed-environment` error on modern macOS (Homebrew) and Debian/Kali (PEP 668).

```bash
git clone https://github.com/yourusername/otacon.git
cd otacon

# create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows (PowerShell)

# install
pip install -e .

# verify
otacon --help
```

After activation the `otacon` command is available in your shell. Leave the
environment with `deactivate`; next time just re-run `source .venv/bin/activate`
(no need to reinstall).

> **Note (macOS / Kali):** if `pip` is missing, use `python3 -m venv` as above —
> the venv ships its own `pip`. The `aiodns` dependency needs the `c-ares`
> system library; if the build fails, install it with `brew install c-ares`
> (macOS) or `sudo apt install libc-ares-dev` (Debian/Kali).

## Usage

### Scan a domain

```bash
otacon scan example.com
```

### Export reports

```bash
# JSON — full forensic data (IPs, MX records, scoring reasons)
otacon scan example.com --json report.json

# Markdown — ready to paste into a ticket/issue
otacon scan example.com --markdown report.md
```

### Options

```bash
otacon scan example.com --no-http          # DNS only (faster)
otacon scan example.com -c 100             # more concurrent requests
otacon scan example.com --all              # show unregistered variants too
```

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
Otacon · target: github.com
┏━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃     ┃ Domain             ┃ Type        ┃         Risk ┃ Signals              ┃
┡━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│  ●  │ githubupdate.com   │ combosquat  │  90 critical │ DNS, MX, SSL, HTTP   │
│  ●  │ bithub.com         │ typo        │  88 critical │ DNS, MX, SSL, HTTP   │
│  ◑  │ github-login.com   │ combosquat  │  50 medium   │ DNS, SSL, HTTP 404   │
└─────┴────────────────────┴─────────────┴──────────────┴──────────────────────┘
```

## Interpreting results

**Otacon flags candidates, it does not pass verdicts.** A high score means a
domain technically *matches the profile* of a fake (registered, has MX, SSL, a
live service) — but the final judgment belongs to the analyst.

Common cases that need manual verification:

- **Legitimate owner domains** — e.g. `googlemail.com` is a real Google domain
  despite a `critical` score. Exclude these via `--exclude` / `--exclude-file`.
- **Parked / for-sale domains** — often have MX and SSL but run no active
  phishing. Still worth monitoring (they can be weaponized later).
- **Defensive registrations by competitors or brand protection** — sometimes
  the owner bought the variants preemptively.

Practical workflow: sort by risk → filter out known-good domains with a
whitelist → manually verify `critical`/`high` (open in a sandbox, inspect the
content, compare the registrar and registration date in WHOIS). Automation
narrows the field from hundreds of variants down to a dozen real candidates —
a human does the rest.

## Architecture

```
otacon/
├── permutations.py   # variant generation engine (6 techniques)
├── resolver.py       # async DNS/MX/SSL/HTTP (semaphore + connection pooling)
├── scoring.py        # transparent rule-based risk engine
├── reporters.py      # output: table / json / markdown
├── models.py         # Pydantic models (type safety + serialization)
├── theme.py          # consistent color palette (single source of truth)
└── cli.py            # Typer + Rich entrypoint
```

Design decisions:

- **async-first** — hundreds of domains checked concurrently (seconds instead
  of minutes), bounded by a semaphore so the DNS resolver isn't flooded.
- **transparent scoring** — rules instead of ML; the user sees WHY something
  got its score (the `risk_reasons` field).
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
