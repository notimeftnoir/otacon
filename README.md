<p align="center">
  <img src="https://raw.githubusercontent.com/notimeftnoir/otacon/main/assets/brand/otacon-header-v2.svg" alt="Otacon — domain impersonation detection" width="760">
</p>

<p align="center">
  <a href="https://github.com/notimeftnoir/otacon/actions/workflows/ci.yml"><img
    src="https://img.shields.io/github/actions/workflow/status/notimeftnoir/otacon/ci.yml?branch=main&style=flat&logo=githubactions&logoColor=white&label=CI"
    alt="CI status"></a>
  <a href="https://pypi.org/project/otacon/"><img
    src="https://img.shields.io/pypi/v/otacon?style=flat&logo=pypi&logoColor=white&label=PyPI" alt="PyPI version"></a>
  <a href="https://pypi.org/project/otacon/"><img
    src="https://img.shields.io/pypi/pyversions/otacon?style=flat&logo=python&logoColor=white"
    alt="Supported Python versions"></a>
  <a href="https://github.com/notimeftnoir/otacon/blob/main/LICENSE"><img
    src="https://img.shields.io/pypi/l/otacon?style=flat&color=blue" alt="MIT licence"></a>
</p>

<p align="center">
  <a href="#install"><b>Install</b></a> ·
  <a href="#one-minute-tour"><b>Tour</b></a> ·
  <a href="#the-triage-console"><b>Console</b></a> ·
  <a href="#what-it-looks-for"><b>Detection</b></a> ·
  <a href="https://github.com/notimeftnoir/otacon/blob/main/docs/USAGE.md"><b>Usage</b></a> ·
  <a href="https://github.com/notimeftnoir/otacon/blob/main/docs/SCORING.md"><b>Scoring</b></a> ·
  <a href="https://github.com/notimeftnoir/otacon/blob/main/docs/FAQ.md"><b>FAQ</b></a>
</p>

<p align="center">
  <b>Otacon finds the domains impersonating yours — before a phishing campaign uses them.</b><br>
  It generates hundreds of lookalikes, checks which are actually registered, and
  scores each one by how much it behaves like a real attack.<br>
  <sub>One command · under a minute · no paid APIs · passive only</sub>
</p>

---

## Install

```bash
pipx install otacon      # isolated global install (recommended)
pip install otacon       # or into an active virtualenv
```

Python 3.12+ on Linux, macOS or Windows. No system libraries needed — the DNS
engine (`pycares`) ships prebuilt wheels with `c-ares` built in.

## One-minute tour

```bash
otacon scan example.com            # scan and print the verdict
otacon                             # or work the findings in the console
```

<p align="center">
  <img src="https://raw.githubusercontent.com/notimeftnoir/otacon/main/assets/brand/demo-scan.svg"
    alt="otacon scan example.com — verdict card, severity spread, and the ten riskiest registered lookalikes with the reason each one matters"
    width="860">
</p>

<p align="center"><sub><i>Real output, not a mock-up: <code>example.com</code> — 240 permutations,
82 registered lookalikes, the ten riskiest and why each one matters. Registrations change
daily, so your scan will differ.</i></sub></p>

Every run ends with the same three things: **a verdict in plain words**, the
**severity spread**, and **one line per finding** with the reason it is there.

```bash
otacon scan example.com --no-http          # DNS only — roughly 3× faster
otacon scan example.com --top 10           # just the riskiest rows
otacon scan example.com --html report.html # self-contained report to hand over
otacon scan example.com --fail-on high     # CI gate: exit 2 on high or critical
otacon watch --add example.com             # keep it on the list, print cron lines
otacon generate example.com -o list.txt    # offline wordlist, no network traffic
```

Global flags (`--quiet`, `--debug`, `--theme`, `--ascii`, `--version`) go
**before** the subcommand; everything else goes after it.

<details>
<summary><b>Exit codes and report formats</b></summary>

<br>

| Exit code | Meaning |
|---|---|
| `0` | Scan completed — nothing at or above `--fail-on`, or `--fail-on` was not passed |
| `1` | Runtime error (bad input, file I/O) |
| `2` | Threshold breached — at least one registered variant met it |

Reports are written with `--json`, `--markdown`, `--html` and `--csv`. Pass as
many as you like: every format renders from the same in-memory report, so they
always agree. Details in [`docs/OUTPUT.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/OUTPUT.md).

A scan whose resolver is failing looks exactly like a clean one, so Otacon
counts its DNS failures and refuses to report an all-clear once they pass 20%
of lookups — it says the scan was **inconclusive** instead.

</details>

---

## The triage console

A scan of a busy brand returns a few hundred rows of which a handful matter.
`otacon` opens on the answer to *am I in trouble* — the verdict, the spread,
what moved since last time, and the three rows worth opening first.

<p align="center">
  <img src="https://raw.githubusercontent.com/notimeftnoir/otacon/main/assets/brand/demo-overview.svg"
    alt="The console's overview screen: verdict, severity spread, and the three findings to open first"
    width="860">
</p>

`enter` goes on to the table. The dossier on the left tracks the cursor —
every signal with a one-line explanation of what it means, then the full
scoring breakdown — and the table on the right is every finding, worst first.

<p align="center">
  <img src="https://raw.githubusercontent.com/notimeftnoir/otacon/main/assets/brand/demo-tui.svg"
    alt="The console's triage table: dossier pane on the left, findings on the right, severity bands named in the gutter"
    width="860">
</p>

One hand works it: `j`/`k` move, `1`–`5` filter to a severity, `/` searches,
`space` marks rows and `t` / `e` / `a` act on everything marked. `?` opens a
glossary of every key, band, flag and technique.

<details>
<summary><b>The full key map</b></summary>

<br>

| Key | Action |
|---|---|
| `↑` `↓` or `j` `k` | Move between rows |
| `enter` | From the overview, open the full table |
| `1` … `5` | Show one severity only — critical, high, medium, low, safe. Again lifts it. |
| `0` | Show every severity |
| `/` | Filter by part of a domain name. `esc` clears it. |
| `u` | Also show variants nobody has registered |
| `s` | Change the order: risk, name, age, technique |
| `f` | Dim everything below the worst band present |
| `b` | Swap the severity glyph for a full bar |
| `space` | Mark this row and move on |
| `v` | Mark everything the filter shows, or clear the marks |
| `o` | Open the site — warns first |
| `w` | Look up when the domain was registered |
| `r` | Re-check the selected row now |
| `t` | Write abuse notices for the marked rows |
| `e` | Export the marked rows as JSON |
| `x` | Export every row the filter shows |
| `a` | Wave the marked rows through, now and in future scans |
| `c` | What changed since the last scan of this target |
| `,` | Settings, the allow-list and the watchlist |
| `?` | Glossary — keys, score bands, flags, techniques |
| `q` | Quit |

Keys that act on a row act on every marked row instead, once anything is marked.

</details>

Running `otacon` bare asks for a target and how deep to look — **Quick**,
**Standard** or **Thorough** — then scans inside the console, findings
appearing as they are scored. `esc` stops a scan and keeps what it found.

Every scan is kept on disk, so the start screen lists what you looked at
before and reopens any of it **offline**. `otacon tui --from report.json`
reads a report from anywhere, so a nightly `otacon -q scan` in CI can be
triaged by hand the next morning without touching the network.

---

## What it looks for

**12 permutation techniques**, modelled on real campaigns, plus
**Certificate Transparency discovery** — which surfaces lookalikes already
holding a certificate that no permutation rule would have guessed.

<details>
<summary><b>Every technique, with a real example</b></summary>

<br>

| Technique | Example (`example.com`) | Real attack vector |
|---|---|---|
| **Homoglyph** | `examp1e.com`, `ex4mple.com` | Visual identity — humans can't tell the difference |
| **IDN / Punycode** | `xn--exampe-7db.com` *(`l` → ł)* | ACE-encoded Unicode that browsers may render natively |
| **Typo** | `exmple.com`, `exsmple.com`, `exampel.com` | Fat-finger typing on QWERTY keyboards |
| **Combosquat** | `example-login.com`, `secureexample.com` | Adds a "trust" keyword — common in phishing email links |
| **TLD swap** | `example.io`, `example.top`, `example.icu` | Same name, different (often cheap, often abused) TLD |
| **Subdomain spoof** | `example.com.login.net` | Your domain as a label; URL-bar trickery |
| **Bitsquat** | `axample.com` (`e`→`a` is one bit flip) | DRAM/DNS memory errors flip a single bit |
| **Hyphenation** | `ex-ample.com` | Insert or remove a hyphen |
| **Soundsquat** | `eksample.com` | Phonetic substitution (ph/f, c/k, s/z, x/ks) |
| **Vowel swap** | `exomple.com`, `exumple.com` | Replace one vowel with another |
| **Plural** | `shops.com` ← `shop.com` | Singular ↔ plural |
| **WWW-merge** | `wwwexample.com` | Dot dropped between "www" and the domain |

Each variant is reported once, under the first technique that produced it, and
the original domain is never included — see
[`docs/USAGE.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/USAGE.md#reading-a-report)
for why that matters when you read a report.

The homoglyph table covers all 26 letters, and every Unicode entry is
cross-checked against Unicode's own
[confusables.txt](https://www.unicode.org/Public/security/latest/confusables.txt):
19 of the 25 share a UTS&nbsp;#39 skeleton with the letter they imitate. The
other six (Cyrillic `к`, `п`, `т`, `ь`, plus `ł` and `í`) are kept on
purpose — UTS&nbsp;#39 folds them elsewhere, but they render close enough in
the sans-serif fonts browsers and mail clients use that real campaigns exploit
them. Each is labelled as such in the source, so nothing in the table is an
unlabelled guess.

</details>

<details>
<summary><b>Every signal behind a score</b></summary>

<br>

For each variant that resolves, Otacon gathers these and turns them into one
explained score. Each group is a flag you can switch off for a faster or
quieter scan.

| Group | Signals |
|---|---|
| **Reachability** | A / AAAA records, HTTP status, redirect target, server header, NXDOMAIN-hijack canary |
| **Mail** | MX records, SPF, DMARC policy — a lookalike with mail and no enforced DMARC is a ready-made sender |
| **TLS** | Certificate issuer, age, and whether its SAN actually covers the host |
| **Brand cloning** | Page-title similarity to yours, and a favicon MurmurHash3 match (the Shodan/Censys hash) |
| **Credential capture** | Password and auth inputs detected in the served page |
| **Reputation** | Spamhaus DBL and SURBL listings, passively over DNS |
| **Registration** | Creation date via RDAP over HTTPS, falling back to port 43 WHOIS |
| **Discovery** | Certificate Transparency logs |

Three classifiers then override the arithmetic: a **sinkholed** or
law-enforcement-seized domain drops to zero, so does a **defensive
registration** that redirects to you without mail, and a **parked** domain has
its traffic signals ignored. Every point value is in
[`docs/SCORING.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/SCORING.md).

</details>

---

## Who it's for

Attackers register `github-update.com`, `paypa1.com`, `goog1e.com` weeks — or
days — before the attack. By the time anyone notices, credentials are gone.

- **Blue team / SOC** — scheduled audits of your own brand, so a new fake with
  mail or a fresh registration is caught in hours, not after the incident.
- **Pentest / red team** — reconnaissance: the lookalikes that already exist
  against a client's brand, for scope or for social-engineering tests.
- **Brand protection** — hundreds of variants in one shot, exported as
  JSON/HTML for the legal team.
- **CI/CD** — `--fail-on critical` blocks a release while an impersonation is
  live.

Otacon is **passive only**: DNS queries, a TLS handshake, one HTTP GET per
variant. No exploit attempts, no auth, no scraping at scale.

---

## Documentation

| Document | What's in it |
|---|---|
| [`docs/USAGE.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/USAGE.md) | Every CLI flag, the five subcommands, the console key map, what Otacon remembers |
| [`docs/SCORING.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/SCORING.md) | Every signal and its point value, the risk bands |
| [`docs/OUTPUT.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/OUTPUT.md) | The five output formats and the JSON schema |
| [`docs/CI.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/CI.md) | Ready-to-paste GitHub Actions and GitLab CI pipelines |
| [`docs/FAQ.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/FAQ.md) | Legality, speed, IDN handling, troubleshooting |
| [`docs/DESIGN.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/DESIGN.md) | Architecture and design rationale |

Four themes ship with it — `midnight`, `daylight`, `vision` (colour-vision
safe) and `mono` — selected with `--theme`, `OTACON_THEME`, or `NO_COLOR`.
`--ascii` degrades every block, arrow and box-drawing character for limited
fonts.

<details>
<summary><b>How it compares to dnstwist</b></summary>

<br>

[`dnstwist`](https://github.com/elceef/dnstwist) is the OG tool in this space.
The two solve overlapping problems with different priorities.

| | **Otacon** | **dnstwist** |
|---|---|---|
| Risk **score** with explained signals | ✓ 0–100, every point sourced | ✗ raw signals only |
| Defensive-registration flag | ✓ on redirect-to-original | ✗ |
| CI/CD exit-code gating | ✓ `--fail-on` | ✗ |
| Self-contained HTML report | ✓ zero JS, pure-CSS filters, SVG charts, defanged IOCs | partial (`--format html`) |
| Keyboard triage console | ✓ the default surface | ✗ |
| Scan memory, reopened offline | ✓ | ✗ |
| Automated abuse takedown notice | ✓ formatted draft with technical evidence | ✗ |
| Permutation techniques | 12 (with regional combosquatting for `.pl`, `.de`, `.fr`) | 13+ |
| Screenshots of pages | ✗ | ✓ |
| Fuzzy/phonetic dictionary attacks | ✓ soundsquat | ✓ |
| Registration data enrichment | RDAP over HTTPS + WHOIS fallback | WHOIS + GeoIP |

**Use dnstwist if** you want screenshots, fuzzy hashing or deeper enrichment.
**Use Otacon if** you want an explained risk score, defensive-flag detection
and a CI-friendly exit code.

</details>

---

## Licence and ethics

**MIT.** Use it freely — on domains you own, domains inside an authorized
engagement with written scope, or domains you have explicit permission to
monitor. Not to harass, dox, or build attack tooling.

See [`CONTRIBUTING.md`](https://github.com/notimeftnoir/otacon/blob/main/CONTRIBUTING.md)
for the dev setup and lint gates, and
[`SECURITY.md`](https://github.com/notimeftnoir/otacon/blob/main/SECURITY.md)
for the disclosure policy. If Otacon helped on a defence engagement,
[say hi](https://github.com/notimeftnoir/otacon/issues) — feedback shapes the
roadmap.
