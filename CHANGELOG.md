# Changelog

All notable changes to Otacon are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--no-whois` CLI flag to bypass WHOIS / RDAP lookups, preventing registry rate-limits and IP blocking during high-volume scans.
- European ccTLDs (`.pl`, `.de`, `.uk`, `.eu`, `.fr`) to `_ALT_TLDS` mutation table.
- `--resolver` / `-r` to query specific DNS servers instead of the system resolver.
- `diacritic` technique: one diacritic added or dropped, or all dropped (`allegro` -> `allęgro`,
  `żabka` -> `zabka`).
- Parking detected from nameservers (Sedo, Bodis, ParkingCrew, Afternic, ParkLogic, …) and from
  "domain for sale" titles in Polish, German, French, Spanish, Italian, Dutch and Russian.
  New `ns_records` field, fetched for registered variants only.
- Threat intel: OpenPhish and Phishing Army feeds, downloaded whole, cached for 6 h and matched
  locally (lookalike names never leave the machine). A listed variant scores +40 and a redirect
  home no longer clears it. URLhaus is queried per registered variant only when `ABUSECH_AUTH_KEY`
  is set. `--no-intel` turns all of it off.
- Brand mentions: hosts in those feeds that carry the brand in their name
  (`allegro.id-23843.click`) are listed under `discovered` in the report. Most real phishing
  looks like this, and no permutation can produce it (9,574 such hosts for `allegro`).
- Mail posture: SPF on a registered lookalike scores +10 (set up to send mail), and the scan
  warns when your own domain has no DMARC policy or only `p=none`, i.e. anyone can send email
  as it. New `has_spf`, `target_spf` and `target_dmarc` fields.
- Favicon fingerprint: live lookalikes get a Shodan-compatible `favicon_hash`
  (`http.favicon.hash:<n>` finds other servers running the same kit); serving the target's exact
  favicon scores +20 as a clone. Pure-stdlib MurmurHash3, verified against `mmh3`.
- `dns_inconclusive` per result and a warning when DNS never answered a variant: its status is
  unknown, which is no longer reported as "not registered".
- Extended multi-part TLD coverage in `_COMMON_MULTI_TLDS` (`ac.uk`, `gov.uk`, `edu.au`, `gov.au`, `waw.pl`).
- Verdict card at the end of every scan: plain-language headline, risk distribution bar
  and counts. Each table row now lists the domain's two strongest reasons.
- Staged scan view: variant breakdown, a progress bar with a running tally of registered
  and dangerous hits plus time left, and a live table capped to the riskiest rows.
- *Next steps* hints after a scan, grouped `--help` panels with examples.
- Interactive mode: a dossier card explaining every signal of the picked domain, friendlier
  prompts, and a short intro animation (interactive colour terminals only; disable with
  `OTACON_NO_ANIMATION=1`).

### Changed
- Brand gradient wordmark with the Cyrillic homoglyph highlighted; lighter table style.
- The progress spinner pulses the risk density ramp instead of Braille dots, which
  Windows console fonts lack.
- `assets/brand/demo-scan.svg` regenerated with the new layout.

### Removed
- **BREAKING:** dropped Python 3.10 support (EOL October 2026). Patched `filelock`
  (a transitive dependency via `tldextract`) requires Python 3.11+.

### Fixed
- IDN brands (`żabka.pl`) were rejected as invalid, and their punycode form was permuted as the
  literal `xn--…` string. Targets are now ACE-encoded on input and decoded before permuting.
- Page titles kept `&nbsp;` as U+00A0 because whitespace was collapsed before entities were
  decoded, so phrase matching and title similarity missed such pages.
- DNS false negatives: every query that timed out counted as "not registered". Queries are now
  capped at 32 in flight and retried on timeout/SERVFAIL/REFUSED (NXDOMAIN is final). On
  `example.com` through 1.1.1.1 this finds 84-85 registered variants on every run instead of 73-78.
- Fixed critical defensive detection bypass where domains redirecting to target were cleared to 0 risk despite having active MX mail servers.
- Fixed asymmetric timeout in `Resolver._probe_http`: when HTTP answers first, HTTPS now gets a 2 s grace window instead of the full 15 s deadline, so a firewalled port 443 no longer stalls the scan while a fast `301 → https` still yields the HTTPS page title.
- Enforced deterministic result sorting in scan reports (`-risk_score`, `domain`) for clean CI artifact diffing.
- Guarded against negative SSL certificate age scoring from future `notBefore` timestamps or clock skew.

### Security
- `certifi` 2026.10.23 (PYSEC-2026-4320) and `filelock` 4.2.4
  (CVE-2026-112907, CVE-2026-112913, CVE-2026-112940).
- Takedown notice rendered attacker-controlled fields (page title, certificate issuer,
  MX hosts) as Rich markup: a `<title>[/]</title>` crashed interactive mode and
  `[link=…]` planted a clickable link in the terminal. Now printed as literal text.
- HTTP/TLS probes no longer connect to non-global addresses that `is_private` misses,
  notably `100.64.0.0/10` (carrier-grade NAT, Tailscale tailnets).
- Terminal escape sequences are stripped from the certificate issuer CN, the `Server`
  header and MX hostnames, as they already were from page titles and `Location`.

## [1.1.0] — 2026-10-14

### Added
- Pure-CSS filtering in HTML reports: 100% CSP compliant (`default-src 'none'`) zero-JS
  table filtering (`All`, `Threats`, `Critical`, `High`, `MX`) using CSS radio selectors.
- Inline SVG risk distribution chart with color-coded legend embedded directly in HTML reports.
- Abuse / Phishing takedown notice generator in interactive TUI (`[t]akedown`), producing
  structured reports containing all technical incident evidence (IPs, MX, SSL, HTTP title, defanged IOC).
- RDAP over HTTPS protocol support with graceful fallback to TCP port 43 WHOIS.
- Regional combosquatting dictionaries with targeted keyword sets for `.pl`, `.de`, and `.fr`.
- Cyrillic homoglyph `О` (U+041E) wordmark branding in console banners and HTML reports.

### Fixed
- Fixed critical relative redirect scoring bypass where relative `Location: /path` headers
  caused malicious lookalikes to be falsely flagged as defensive redirects.
- Fixed CLI output path validation (`safe_cli_path`) allowing operators to write reports to
  explicit absolute paths while maintaining strict protection against NUL-bytes and traversal.
- Concurrency race optimization in resolver: canceled slow HTTP probes immediately upon fast
  HTTPS completion, reducing scan latency.

### Security
- OPSEC hardening when inspecting lookalike domains from interactive mode: warning prompt,
  defanged IOC display (`hxxps://...`), and direct sandbox links (urlscan.io).
- Domain names in HTML reports are defanged (`[.]`) and use `rel="noopener noreferrer"`.
- Supply chain vulnerability resolution: upgraded `urllib3` (>=2.8.0) and `pyjwt` (>=2.15.0).

## [1.0.3] — 2026-10-10

### Fixed
- `--debug` / `-v` now logs to **stderr**, as `--help` and the docs always
  said. It used to write to stdout, mixing hundreds of log lines into the
  results table, and under `--quiet` the log was silenced completely. Now
  `otacon -q -v scan … > report.json 2> debug.log` gives clean JSON plus a
  separate diagnostic log.
- A lookalike serving a certificate with a non-positive serial number no
  longer prints a `CryptographyDeprecationWarning` into the middle of the
  scan output. The certificate signals are still read from it.

### Security
- Every `pip install` in CI and in the publish workflow now installs from a
  hash-pinned lock file with `--require-hashes`, so a tampered or substituted
  package fails the install instead of running (OpenSSF Scorecard
  Pinned-Dependencies). The publish job no longer installs `build` unpinned.
- The publish workflow refuses to run when the pushed tag does not match the
  version in `pyproject.toml`. Before, a mismatched tag could attach the
  previous version's files to the new GitHub release before failing.
- `SECURITY.md` rewritten: reports go through GitHub Private Vulnerability
  Reporting, with a support table, response timeline, 90-day coordinated
  disclosure and a safe-harbor clause.

### Changed
- Dependencies: `cryptography` 50.0.2, `asyncwhois` 1.1.15 (which brings
  `whodap` 0.2.1 on the `httpx2` HTTP stack). WHOIS lookups were checked live
  against the new stack.
- No system `c-ares` library is needed any more. `pycares` wheels bundle it
  for CPython 3.10–3.14 on Linux, macOS and Windows, so the install note and
  the CI `apt-get` steps are gone.
- The CycloneDX SBOM built in CI lists Otacon itself as the root component
  again (`cyclonedx-py --pyproject`), not just its dependencies.
- The project page on PyPI shows the logo and the demo scan, and its links to
  the docs work: the README now uses absolute URLs, since PyPI does not
  resolve repository-relative paths.
- Docs: measured scan timings replace the old "~10 seconds" claim, the README
  demo is labelled as a dated snapshot, the CI examples use current action
  versions and GitLab `rules:`, and CONTRIBUTING covers the hash-locked dev
  install and how to regenerate the lock files.

## [1.0.2] — 2026-10-07

### Fixed
- Wildcard SAN matching now follows RFC 6125 §6.4.3: a `*.example.com` cert
  covers exactly one label (`a.example.com`) and no longer matches deeper hosts
  like `a.b.example.com` or the bare parent. The previous `endswith` check let a
  cert for an unrelated deep subdomain wrongly clear the SSL SAN-mismatch signal.
- `--weights-file` overrides with an unknown key (a typo such as
  `points_reslves`) or a private/dunder attribute name are now logged under
  `--debug` and skipped, instead of being silently dropped — a broken weights
  file no longer reads as if it had taken effect. Valid overrides in the same
  file still apply.

## [1.0.1] — 2026-09-25

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
- `--weights-file` with syntactically-valid but non-object JSON (e.g. a
  top-level list) no longer crashes with a raw `AttributeError` traceback —
  the type check now lives on `ScoringWeights` itself (the class that
  actually assumes a dict) rather than duplicated at the CLI call site, and
  raises a clean `typer.BadParameter`/`TypeError` like every other malformed
  weights-file case. A weights-file containing literal JSON `null` is still
  treated as "no overrides" (falls back to defaults), unchanged from before.
- Terminal/Markdown/HTML verdict banners' "fresh <Nd>" count and label now
  all read the actual `AGE_FRESH_DAYS` threshold via a single shared
  `scoring.count_fresh()` helper instead of three separately hardcoded/
  duplicated computations, and the printed label now always matches the
  threshold instead of a hardcoded `<7d`.
- CSV export now runs the `domain` column through the same formula-injection
  guard (`_csv_safe`) already applied to `page_title`/`redirects_to`.

### Security
- The resolver strips Unicode control/format/line-separator characters
  (categories Cc, Cf, Zl, Zp — covering C0 and C1 control codes, e.g. the
  8-bit CSI equivalent U+009B, plus format chars like U+202E right-to-left
  override and the U+2028/U+2029 separators) from a page `<title>` and the
  redirect `Location` header before either is echoed to the terminal, HTML
  report, or CSV export.

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
