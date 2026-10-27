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
  <a href="#quick-start"><b>Quick start</b></a> ·
  <a href="#detection-techniques"><b>Techniques</b></a> ·
  <a href="https://github.com/notimeftnoir/otacon/blob/main/docs/USAGE.md"><b>Usage</b></a> ·
  <a href="https://github.com/notimeftnoir/otacon/blob/main/docs/SCORING.md"><b>Scoring</b></a> ·
  <a href="https://github.com/notimeftnoir/otacon/blob/main/docs/CI.md"><b>CI/CD</b></a> ·
  <a href="https://github.com/notimeftnoir/otacon/blob/main/docs/FAQ.md"><b>FAQ</b></a>
</p>

> **Otacon** finds domains impersonating yours — **typosquats, homoglyph fakes, combosquats, IDN/punycode tricks** and more. It generates hundreds of variants, checks which are actually registered, and scores each by real-world phishing risk. One command, under a minute, no paid APIs.

<p align="center">
  <img src="https://raw.githubusercontent.com/notimeftnoir/otacon/main/assets/brand/demo-scan.svg"
    alt="otacon scan example.com — 234 permutations checked, registered lookalikes ranked by risk"
    width="860">
</p>

<sub><i>Real output: a full scan of <code>example.com</code> recorded on 2026-10-26 — 239 permutations, 71 registered lookalikes at the time; the verdict card and the ten riskiest rows. Registrations change daily, so a scan today shows different domains. Regenerate with <code>python tools/render_demo_svg.py example.com assets/brand/demo-scan.svg</code>.</i></sub>

---

## Install

```bash
pipx install otacon      # isolated global install (recommended)
pip install otacon       # or into an active virtualenv
```

Python 3.11–3.13 on Linux, macOS or Windows. No system libraries are needed:
the DNS engine (`pycares`) ships prebuilt wheels with `c-ares` built in.

## Quick start

```bash
otacon scan example.com                   # full scan: DNS, MX, TLS, HTTP, WHOIS
otacon scan example.com --no-http         # DNS only — roughly 3x faster
otacon scan example.com --fail-on high    # CI gate: exit 2 on high or critical
otacon tui example.com                    # scan, then triage in the console
otacon tui --from report.json             # reopen a saved report
otacon generate example.com -o list.txt   # offline wordlist, no network traffic
otacon                                    # guided interactive mode
```

Global flags (`--quiet`, `--debug`, `--version`) go **before** the subcommand;
everything else goes after it.

| Exit code | Meaning |
|---|---|
| `0` | Scan completed — nothing at or above `--fail-on`, or `--fail-on` was not passed |
| `1` | Runtime error (bad input, file I/O) |
| `2` | Threshold breached — at least one registered variant met it |

Reports are written with `--json`, `--md`, `--html` and `--csv`; pass as many as
you like, since every format renders from the same in-memory report.

---

## Why Otacon?

Phishing campaigns almost always start with a **lookalike domain**. Attackers register `github-update.com`, `paypa1.com`, `goog1e.com` weeks (or days) before the actual attack. By the time anyone notices, credentials are already gone.

Otacon is built for the people who need to find those domains **before the attack lands**:

| Role | Use case |
|---|---|
| **Pentester / red team** | Reconnaissance — find existing lookalikes against the client's brand to include in scope or use in social-engineering tests |
| **Blue team / SOC** | Scheduled audits of your own domain (e.g. a daily CI cron job) to catch a new fake fast, especially one with MX or fresh registration |
| **Brand protection** | Audit hundreds of variants in one shot, export as JSON/HTML for the legal team or DMCA filings |
| **CI/CD gate** | Block deploys when a critical impersonation is live (`--fail-on critical`) |

Otacon is **fully passive**: DNS queries, a TLS handshake, one HTTP GET per variant. No exploit attempts, no auth, no scraping at scale.

---

## Detection techniques

Otacon implements **12 permutation techniques** modeled on real-world attacks. The
homoglyph table covers all 26 letters, not just the handful that are easy to
eyeball, and every Unicode entry in it is cross-checked against Unicode's own
[confusables.txt](https://www.unicode.org/Public/security/latest/confusables.txt):
19 of the 25 share a UTS&nbsp;#39 skeleton with the letter they imitate. The
other six (Cyrillic `к`, `п`, `т`, `ь`, plus `ł` and `í`) are kept on purpose —
UTS&nbsp;#39 folds them elsewhere, but they render close enough in the
sans-serif fonts browsers and mail clients use that real campaigns exploit them.
Each of the six is labelled as such in the source, so nothing in the table is an
unlabelled guess.

| Technique | Example (`example.com`) | Real attack vector |
|---|---|---|
| **Homoglyph** | `examp1e.com`, `ex4mple.com` | Visual identity — humans can't tell the difference |
| **IDN / Punycode** | `xn--exampe-7db.com` *(`l` → ł)* | ACE-encoded unicode that browsers may render natively |
| **Typo** | `exmple.com`, `exsmple.com`, `exampel.com` | Fat-finger typing on QWERTY keyboards |
| **Combosquat** | `example-login.com`, `secureexample.com` | Adds "trust" keyword — common in phishing email links |
| **TLD swap** | `example.io`, `example.top`, `example.icu` | Same name, different (often cheap/abused) TLD |
| **Subdomain spoof** | `example.com.login.net` | Original domain as a label; URL-bar trickery |
| **Bitsquat** | `axample.com` (`e`→`a` is one bit flip) | DRAM/DNS memory errors flip a single bit |
| **Hyphenation** | `ex-ample.com` | Insert/remove a hyphen |
| **Soundsquat** | `eksample.com` | Phonetic substitution (ph/f, c/k, s/z, x/ks) |
| **Vowel swap** | `exomple.com`, `exumple.com` | Replace one vowel with another |
| **Plural** | `shops.com` ← `shop.com` | Singular ↔ plural variation |
| **WWW-merge** | `wwwexample.com` | Dot dropped between "www" and the domain — easy to misread |

Every example above is real output, not an illustration. Each variant is
reported once, under the first technique that produced it, and the original
domain is never included — see [`docs/USAGE.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/USAGE.md#reading-a-report)
for why that matters when you read a report.

---

## Documentation

| Document | What's in it |
|---|---|
| [`docs/USAGE.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/USAGE.md) | Every CLI flag, the four modes, the triage console, whitelisting |
| [`docs/SCORING.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/SCORING.md) | Every signal and its point value, risk-level thresholds |
| [`docs/OUTPUT.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/OUTPUT.md) | The five output formats and the JSON schema |
| [`docs/CI.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/CI.md) | Ready-to-paste GitHub Actions and GitLab CI pipelines |
| [`docs/FAQ.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/FAQ.md) | Legality, speed, IDN handling, troubleshooting |
| [`docs/DESIGN.md`](https://github.com/notimeftnoir/otacon/blob/main/docs/DESIGN.md) | Architecture and design rationale |

---

## Comparison with dnstwist

[`dnstwist`](https://github.com/elceef/dnstwist) is the OG tool in this space. Otacon and dnstwist solve overlapping problems with different priorities.

| | **Otacon** | **dnstwist** |
|---|---|---|
| Risk **score** with explained signals | ✓ 0–100, every point sourced | ✗ raw signals only |
| Defensive-registration flag | ✓ `»` on redirect-to-original | ✗ |
| CI/CD exit code gating | ✓ `--fail-on` | ✗ |
| Self-contained HTML report | ✓ dark theme, zero JS, pure-CSS filters, SVG charts, defanged IOCs | partial (`--format html`) |
| Interactive post-scan triage | ✓ open (OPSEC safe) / whois / takedown / rescan / allow | ✗ |
| Keyboard triage console (`otacon tui`) | ✓ filter by risk, search, live dossier pane | ✗ |
| Automated abuse takedown notice | ✓ formatted draft with technical evidence | ✗ |
| Permutation techniques | 12 (with regional combosquatting for `.pl`, `.de`, `.fr`) | 13+ |
| Visual screenshots of pages | ✗ | ✓ |
| Fuzzy/phonetic dictionary attacks | ✓ soundsquat | ✓ |
| Registration data enrichment | RDAP over HTTPS + WHOIS fallback | WHOIS + GeoIP |

**Use dnstwist if** you want screenshots, fuzzy hashing, deeper enrichment.
**Use Otacon if** you want an opinionated risk score, defensive-flag detection, and a CI-friendly exit code.

---

## Contributing

See [`CONTRIBUTING.md`](https://github.com/notimeftnoir/otacon/blob/main/CONTRIBUTING.md) for the dev setup and the lint gates,
and [`SECURITY.md`](https://github.com/notimeftnoir/otacon/blob/main/SECURITY.md) for the disclosure policy.

---

## License & ethics

**MIT License.** Use it freely.

Otacon is **passive only** — DNS queries, a TLS handshake, a single HTTP GET per variant. No exploit attempts, no brute-forcing, no auth.

**Use only on:**
- Domains you own
- Domains within an authorized security testing engagement (with written scope)
- Domains you have explicit permission to monitor

**Do not use to:** harass, dox, or build attack tooling. If you found this useful for a defense engagement, [say hi](https://github.com/notimeftnoir/otacon/issues) — feedback shapes the roadmap.
