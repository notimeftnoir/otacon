# Changelog

All notable changes to Otacon are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- A malformed `Location` header from a scanned host (`http://[evil`) made
  `urlparse` raise, which aborted scoring for the entire target and discarded
  every other result — one hostile lookalike could deny the whole scan. All
  redirect parsing now goes through a single guarded helper, and an
  unparseable redirect can no longer pass as a defensive registration (which
  would have zeroed that domain's risk score)

### Fixed
- TLD-swap and subdomain-spoof variants skipped the IDNA step the rest of the
  pipeline applies, so an internationalised target emitted 33 variants in raw
  Unicode — a second spelling of names already present in `xn--` form, which
  defeated cross-technique deduplication
- Whitelist entries are canonicalised to punycode before matching; a Unicode
  `--exclude` entry could never match the ACE variants and was silently dead
- Hyphenation no longer emits a hyphen against a label boundary
  (`foo-.example.com`), which RFC 1035 forbids and no registry can serve
- `--quiet` printed no report at all when a multi-domain scan had some targets
  fail: the single and aggregate emitters keyed off different counts, so a
  partial success fell between both branches
- Page titles shown in the results table no longer leak a stray backslash —
  `rich.Text` takes literal text, so the markup escaping was rendering itself
- A malformed `kind_base` in a `--weights-file` was coerced to an integer and
  surfaced as an unrelated error mid-scan; it is now ignored
- The `fresh <7d` counters in the table and Markdown verdict read the shared
  `AGE_FRESH_DAYS` constant instead of an inlined `7`

### Changed
- CI installs `libc-ares-dev` after `apt-get update`, so a stale runner package
  index cannot fail the Linux jobs

## [1.0.0] — 2026-09-19

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
- Weights overridable from a JSON file via `--weights-file`
- Parked-domain and defensive-registration (⚑) detection, so registrations
  that redirect back to the original are not reported as threats

### Scanning
- One or many targets: variadic arguments plus `--domains-file`
- Fully concurrent (`--concurrency`, default 50), bounded to protect the DNS
  resolver and the local file-descriptor limit
- `--no-http` for a DNS-only pass
- Whitelisting via `--exclude` and `--exclude-file`
- NXDOMAIN-hijack detection — resolvers that answer every query are caught by
  a random-nonce canary, and their answers discarded instead of reported as
  hundreds of false positives

### Output
- Colored terminal table that streams hits live as they are found
- JSON, Markdown, HTML and CSV reports; JSON and HTML also in aggregated form
  covering every target of a multi-domain run
- `--fail-on <level>` exits 2, for use as a CI/CD gate
- `--quiet` writes JSON to stdout for piping

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
- CSV cells are neutralised against spreadsheet formula injection (CWE-1236)
- Every value interpolated into the HTML report is escaped, and report paths
  are confined to the working directory
