# Changelog

All notable changes to Otacon are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
