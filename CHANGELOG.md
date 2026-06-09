# Changelog

All notable changes to Otacon are documented here.

## [Unreleased]

## [1.0.1] — 2026-06-09

### Security
- HTTP probing now streams responses and caps the body read at 64 KB
  (`resolver._read_capped` / `_MAX_BODY_BYTES`), preventing a hostile lookalike
  server from OOM-ing the scanner with a giant body or a gzip decompression bomb.
  Connection pool is also bounded to the scan concurrency via `httpx.Limits`.
- Interactive JSON export (`_export_result`) is now confined to the current
  working directory: absolute paths and `..` escapes are rejected after
  canonicalisation (the previous `..`-substring check let absolute paths through).
- TLS-warning suppression scoped to client construction instead of a
  process-wide `warnings.filterwarnings` (no longer pollutes importers).
- Interactive mode `_validate_domain` now calls `is_valid_domain()` — previously
  only checked for non-empty input, allowing malformed strings (schemes, paths,
  control characters) to reach the scan pipeline.
- `watch.notify()` now uses `is_safe_webhook_url()` instead of a bare
  `startswith` check — prevents SSRF via RFC 1918 / loopback webhook URLs when
  `notify()` is called outside the CLI path.
- Interactive "open in browser" action now shows a risk warning and requires
  confirmation before opening a suspicious domain in the default browser.

### Fixed
- Age cell threshold inconsistency: `_age_cell` in `reporters.py` and
  `html_report.py` previously styled all domains < 30 days as critical (red),
  mismatching the "fresh < 7d" count in the verdict banner. Now: < 7 d = red,
  7–30 d = yellow, matching the scoring thresholds.
- Output file generation in `scan` command: `to_json()` and `to_markdown()` were
  called unconditionally even when no output path was provided. All four formats
  (`--json`, `--markdown`, `--csv`, `--html`) are now guarded by a path check.

### Added
- `--debug` flag that surfaces graceful-degradation events (DNS/WHOIS/HTTP/webhook
  failures) via an `otacon.*` logger; silent by default.
- CI dependency audit job (`pip-audit`) and a Dependabot config for pip + actions.
- HTML report: `.age-warn` CSS class for domains 7–30 days old (yellow).

### Changed
- Hardened release workflow: PyPI Trusted Publishing (OIDC, no long-lived token),
  least-privilege `permissions:`, a protected `pypi` environment, and the publish
  action pinned to a commit SHA.
- Banner cleanup: removed the `∴` glyph next to `OTACON` in CLI and HTML output.
- Made `DEFAULT_CONCURRENCY` a public constant in `resolver.py`.
- Unified trailing-dot stripping for defensive-redirect host matching in `scoring.py`.
- Added `noopener` alongside `noreferrer` on domain links in the HTML report.
- Dropped unused `re.DOTALL` flag from the HTML `<title>` regex.

### Docs
- README rewritten and expanded: table of contents, role-based use cases, full CLI
  reference, CI/CD examples (GitHub Actions + GitLab CI), comparison with dnstwist,
  FAQ, troubleshooting.
- `docs/DESIGN.md` expanded: module map, async concurrency diagram, error-handling
  matrix, testing strategy, performance characteristics, roadmap.

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
