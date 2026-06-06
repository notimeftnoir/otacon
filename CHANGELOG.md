# Changelog

All notable changes to Otacon are documented here.

## [1.0.0] — 2026-06-06

Initial public release.

### Detection techniques (11)
- Homoglyph — Unicode/ASCII visual substitution
- IDN/Punycode — ACE-encoded unicode homoglyphs (`xn--`)
- Typo — omission, duplication, transposition, QWERTY adjacency
- Combosquat — appended bait words (login, secure, verify…)
- TLD swap — same name, different TLD
- Subdomain spoof — original domain embedded as a label (`example.com.login.net`)
- Bitsquat — single-bit flip (RAM/DNS memory errors)
- Hyphenation — inserting/removing a hyphen
- Soundsquat — phonetic substitution (ph/f, c/k, s/z…)
- Vowel swap — replace each vowel with every other vowel
- Plural — singular/plural suffix variation

### Signals collected per variant
- A record (DNS resolution)
- MX record (email-phishing readiness)
- SSL certificate (active HTTPS infrastructure)
- HTTP probe + redirect detection
- Page title fingerprint (high/critical rows)
- Domain age via WHOIS (strongest phishing predictor)

### Scoring
- Rule-based 0–100 score with `risk_reasons` (transparent, no ML)
- Levels: safe · low · medium · high · critical

### Output formats
- Colored terminal table (Rich) with live streaming as hits are detected
- JSON (full forensic data)
- Markdown (paste into tickets/issues)
- HTML (self-contained dark-palette report)

### Modes
- `scan` — full DNS/MX/SSL/HTTP scan
- `watch` — baseline diff (NEW / CHANGED / GONE), optional interval loop + webhook notify
- `generate` — offline variant preview (no network)
- Interactive — guided mode when run with no arguments

### Other
- `--fail-on` exit codes for CI/CD pipelines
- `--exclude` / `--exclude-file` whitelist
- Post-scan action loop: open in browser, WHOIS, export, rescan, allow
- Auto-suggest whitelisting for defensive (⚑) registrations
- `--version` flag
