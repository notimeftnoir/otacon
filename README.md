<p align="center">
  <img src="assets/brand/otacon-readme-header.png" alt="Otacon — domain impersonation detector" width="620">
</p>

<p align="center">
  <a href="https://github.com/notimeftnoir/otacon/actions"><img src="https://github.com/notimeftnoir/otacon/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT">
</p>

Otacon finds domains impersonating yours — typosquats, homoglyph fakes, combosquats. Generates hundreds of variants, checks which are registered, scores each by threat level. Runs in ~10 seconds, no paid APIs.

```
⚠ 3 registered · crit: 1 · mx: 1 · fresh <7d: 1

Otacon · target: github.com
┌────────────────────────────────┬────────────────────┬──────────┬─────┬────┬─────┬──────┐
│ Domain                         │ Risk               │      Age │ DNS │ MX │ SSL │ HTTP │
├────────────────────────────────┼────────────────────┼──────────┼─────┼────┼─────┼──────┤
│ githubupdate.com               │ ███████░  92 crit  │       3d │  ✓  │ ✓  │  ✓  │  200 │
│ combosquat · "GitHub - Security Update Required"                                       │
│ bithub.com                     │ █████░░░  68 high  │       2y │  ✓  │ —  │  ✓  │  301 │
│ typo                                                                                   │
│ githuub.com                    │ ████░░░░  48 med   │      8mo │  ✓  │ —  │  —  │  404 │
│ typo                                                                                   │
└────────────────────────────────┴────────────────────┴──────────┴─────┴────┴─────┴──────┘
Permutations: 143 · registered: 3 · med: 1 · high: 1 · crit: 1
```

## Features

- **11 permutation techniques** — typo, homoglyph (Unicode + ASCII), IDN/punycode, combosquat, TLD-swap, bitsquat, soundsquat, subdomain spoof, vowel-swap, hyphenation, plural
- **Transparent 0–100 risk score** — DNS · MX · SSL · HTTP status · domain age · technique, each signal explained
- **Domain age via WHOIS** — freshly registered lookalikes (<7 days) score highest
- **⚑ defensive flag** — detects redirects back to the original (brand-owner registrations)
- **Watch mode** — continuous monitoring with baseline diff: NEW / CHANGED / GONE
- **Interactive post-scan** — open in browser, WHOIS lookup, re-scan, session allow-list
- **4 export formats** — rich terminal table, JSON, Markdown, self-contained HTML report
- **CI/CD gate** — `--fail-on high` exits 2 when any high/critical domain is found

## Install

**Recommended — isolated global install via pipx:**

```bash
pipx install git+https://github.com/notimeftnoir/otacon.git
```

**Alternative — standard pip into any active virtual environment:**

```bash
pip install git+https://github.com/notimeftnoir/otacon.git
```

> **macOS / Kali:** the `aiodns` dependency needs the `c-ares` system library.  
> `brew install c-ares` (macOS) · `sudo apt install libc-ares-dev` (Debian/Kali)

<details>
<summary>Development install</summary>

```bash
git clone https://github.com/notimeftnoir/otacon.git
cd otacon
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows (PowerShell)
pip install -e ".[dev]"
pytest && ruff check .
```

</details>

## Usage

```bash
otacon                                        # interactive mode (guided prompt)
otacon scan example.com                       # one-shot scan
otacon scan example.com --json r.json --html r.html   # export reports
otacon scan example.com --fail-on high        # CI gate — exit 2 on high/critical
otacon scan example.com --exclude "alias.com" # skip known-good domains
otacon watch example.com --interval 24h \
  --notify https://hooks.example.com/abc      # continuous monitoring + webhook
otacon generate example.com -o variants.txt   # wordlist only, no network
```

> `--no-http` — DNS-only mode (faster, disables ⚑ defensive flag)  
> `--all` — include unregistered variants in the output

**Exit codes** — for CI gating:

| Code | Meaning |
|---|---|
| `0` | clean — nothing at/above the `--fail-on` threshold |
| `1` | runtime error (bad input, network failure) |
| `2` | threshold breached — a domain at/above the level was found |

## How scoring works

Every score is the sum of explicit, explainable signals — no ML, no black box.
The reasons behind each score are exposed in the JSON export (`risk_reasons`) and the
interactive view.

<details>
<summary><b>Signal point values</b></summary>

| Signal | Points |
|---|---|
| **MX record** — ready for email phishing | +25 |
| **Technique** — homoglyph / IDN | +25 |
| &nbsp;&nbsp;subdomain spoof | +22 |
| &nbsp;&nbsp;combosquat | +20 |
| &nbsp;&nbsp;typo | +18 |
| &nbsp;&nbsp;soundsquat | +16 |
| &nbsp;&nbsp;bitsquat · vowel-swap | +15 / +14 |
| &nbsp;&nbsp;hyphenation · plural · TLD-swap | +12 / +10 / +10 |
| **Domain age** — &lt;7 days | +20 |
| &nbsp;&nbsp;&lt;30 days · &lt;90 days | +12 / +5 |
| **SSL** certificate active | +15 |
| **HTTP** 2xx live · 3xx redirect | +15 / +10 |
| &nbsp;&nbsp;4xx · 5xx | +5 / +3 |
| **Resolves** to an IP | +10 |
| **Redirects** elsewhere (non-2xx, non-3xx) | +5 |

Score is capped at 100. Unregistered domains always score 0.

</details>

### Risk levels

| Level | Score | Meaning |
|---|---|---|
| 🔴 **critical** | 80–100 | active infrastructure + email-ready — treat as a live threat |
| 🟠 **high** | 60–79 | registered with serious signals (MX or live site) |
| 🟡 **medium** | 35–59 | registered, some signals — worth watching |
| 🔵 **low** | 15–34 | registered, minimal signals |
| 🟢 **safe** | 0–14 | unregistered or negligible |

> 📐 Architecture, pipeline and design rationale → [`docs/DESIGN.md`](docs/DESIGN.md)

## License

MIT · Passive queries only (DNS, TLS handshake, single HTTP GET). Use on your own domains or within authorized security testing.
