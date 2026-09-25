# Changelog

All notable changes to Otacon are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Replaced the UI glyphs that no common monospace font ships, and which therefore
  rendered as `?` or tofu: the banner hexagons (U+2B21/U+2B22) are now dots, the
  defensive-registration flag (U+2691) is now `»`, and the risk icons are a
  `░▒▓█` density ramp instead of circles with partial or full fill
  (U+25D0-U+25D5, plus U+25CF for critical). `theme.SAFE_GLYPHS`
  records the vetted set and a test holds the UI modules to it.
- `whitelist.txt` is now read back through the same parser that writes it, so an
  entry added by a previous interactive scan is recognised even when the file
  carries CRLF endings or hand-edited casing. Previously the defensive-registration
  writer re-appended those entries on every run.
- The defensive-registration writer now starts a new line before appending to a
  `whitelist.txt` that does not end in one, instead of fusing the file's last
  entry with the first appended domain.

### Changed
- `--exclude-file`, interactive mode's `whitelist.txt`, and the defensive-registration
  writer share one reader (`_validate.parse_domain_list`) instead of three copies of
  the same parse-and-normalise loop.
- Documented the homoglyph table's provenance accurately: 19 of the 25 Unicode
  entries share a UTS #39 skeleton with the letter they imitate, and the other six
  are now labelled in the source as deliberate font-level look-alikes. The previous
  wording claimed every entry was a documented confusable.

## [1.0.0] — 2026-09-20

Initial public release.

### Detection techniques (12)
- Homoglyph — visually identical Unicode/ASCII substitution
- IDN / Punycode — ACE-encoded Unicode homoglyphs (`xn--`)
- Typo — omission, duplication, transposition, QWERTY adjacency
- Combosquat — appended bait words (`login`, `secure`, `verify`…)
- TLD swap — same name, different TLD
- Subdomain spoof — original domain embedded as a label (`example.com.login.net`)
- Bitsquat — single-bit flip, exploiting real RAM/DNS corruption
- Hyphenation — inserting or removing a hyphen
- Soundsquat — phonetic substitution (ph/f, c/k, s/z…)
- Vowel swap — each vowel replaced with every other vowel
- Plural — singular/plural suffix variation
- www-merge — the `www` label merged into the domain (dot omission)

Every technique runs through the same IDNA step, so an internationalised
target yields one canonical `xn--` spelling per variant and cross-technique
deduplication holds. Hyphenation never places a hyphen against a label
boundary (`foo-.example.com`), which RFC 1035 forbids and no registry serves.

### Signals collected per variant
- A and AAAA records — an IPv6-only lookalike resolves in every modern browser
- MX record — readiness for email phishing
- TLS certificate — issuer, age, and SAN/hostname match
- HTTP probe — status, `Server` header, redirect target
- Page title, compared against the target's own — catches cloned pages
- Domain age via WHOIS — the strongest single phishing predictor

### Scoring
- Transparent rule-based 0–100 score with per-result `risk_reasons`; no ML,
  so an operator can always see why a domain scored what it did
- Levels: safe · low · medium · high · critical
- Weights overridable from a JSON file via `--weights-file`; a malformed
  `kind_base` is ignored and reported under `--debug` rather than coerced
  into an integer that fails later mid-scan
- Parked-domain and defensive-registration (⚑) detection, so registrations
  that redirect back to the original are not reported as threats

### Scanning
- One or many targets: variadic arguments plus `--domains-file`
- Fully concurrent (`--concurrency`, default 50), bounded to protect the DNS
  resolver and the local file-descriptor limit
- `--no-http` for a DNS-only pass
- Whitelisting via `--exclude` and `--exclude-file`, canonicalised to
  punycode before matching so a Unicode entry matches its ACE variants
- NXDOMAIN-hijack detection — resolvers that answer every query are caught by
  a random-nonce canary, and their answers discarded instead of reported as
  hundreds of false positives

### Output
- Colored terminal table that streams hits live as they are found
- JSON, Markdown, HTML and CSV reports; JSON and HTML also in aggregated form
  covering every target of a multi-domain run
- `--fail-on <level>` exits 2, for use as a CI/CD gate
- `--quiet` writes JSON to stdout for piping, including when a multi-domain
  scan succeeds only partially

### Modes
- `scan` — full DNS/MX/TLS/HTTP scan
- `generate` — offline variant preview, no network traffic
- Interactive — guided mode when run with no arguments, with a post-scan
  action loop (open in browser, WHOIS, export, rescan, whitelist)

### Security
Otacon connects to attacker-controlled hosts by design, so the scanner itself
is treated as the attack surface:
- Outbound connections are pinned to a pre-vetted IP, closing the DNS-rebinding
  window between the safety check and the connect, and keeping a lookalike from
  steering the scanner at cloud-metadata or RFC1918 addresses
- Response bodies are capped and every probe carries a wall-clock deadline, so
  a hostile host cannot exhaust memory or hold a slot open indefinitely
- A malformed `Location` header from a scanned host (`http://[evil`) cannot
  abort scoring and discard the rest of the run: all redirect parsing goes
  through one guarded helper, and an unparseable redirect can no longer pass
  as a defensive registration and zero that domain's risk score
- CSV cells are neutralised against spreadsheet formula injection (CWE-1236)
- Every value interpolated into the HTML report is escaped, and report paths
  are confined to the working directory
