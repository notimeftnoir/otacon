# Changelog

All notable changes to Otacon are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] — 2026-10-29

A major because the guided prompts are gone: the triage console is the tool
now, and `otacon` with no arguments opens it rather than a questionnaire.

The rest of the release is the interface. Otacon drew the same report through
four renderers, each carrying its own hard-coded copy of the palette, so every
visual change cost three edits and drifted anyway. One palette now feeds all of
them, which is what made the rest possible: four themes, a colour-blind-safe
ramp, a monochrome mark, and an ASCII mode that actually reaches every glyph
rather than only the logo.

Both consoles were rebuilt around the same question. A scan of a real brand
returns a few hundred permutations of which a handful matter, and both
surfaces made you find them yourself. `otacon scan` gave each row up to six
wrapped lines; the triage console dropped you into the table with no verdict
at all, even though it is the surface plain `otacon` opens. Both now lead with
what the scan amounts to, in the same words, and both show one row per finding.

Scores and detection are unchanged. Stored reports gain a `cancelled` field
and are otherwise compatible.

### Added
- A design-token layer (`otacon/ui/`) as the single source of visual truth, with four themes: `midnight` (the existing dark palette), `daylight` for light terminals and printed HTML, `vision` for colour-vision deficiency — red/green is the commonest form and it was exactly the critical/safe pair — and `mono`, which carries severity by glyph density and weight alone. `--theme`, `OTACON_THEME`, and `NO_COLOR` resolving to `mono`.
- `--ascii` and `OTACON_ASCII`, degrading every block, arrow and box-drawing character, Rich's own frames included. `SAFE_GLYPHS` had documented a font budget that nothing could actually degrade to.
- An overview screen: a finished scan opens on its verdict, the severity spread, what moved since the last scan of this target, and the three rows worth opening first with their reasons in words. `enter` goes on to the table.
- Scan presets on the start screen — Quick, Standard, Thorough — with the four protocol-named switches behind an *Advanced* disclosure. Thorough is selected on open, so a preset can never quietly make a scan less thorough than it was before presets existed.
- A live scan view: the stage it is in, the running tally, and findings appearing as they are scored. Certificate Transparency is one slow call before the counter can move, and it used to report nothing at all, so a scan with CT enabled sat on a motionless bar and looked hung.
- `esc` stops a scan and keeps what it found; the report is marked `cancelled` and the verdict says so rather than reading as an all-clear.
- Marks and bulk actions in the triage console: `space` marks a row and moves on, `v` marks everything the filter shows, and `t`, `e` and `a` act on the marked rows. Bulk writes arm and confirm with the count first. Marks are held by domain, not by index, and an action only ever touches rows the filter currently shows.
- `s` cycles the table order (risk, name, age, technique) and `x` exports every row the current filter shows.
- `?` opens a glossary: the keys, the score bands, every flag and every technique in one plain sentence each.
- `f` dims every row below the worst band present, and `b` swaps the severity glyph for the full bar.
- A persistent status bar carrying the active filter, the row count, the marks and the order — this used to live in a toast that disappeared two seconds after it appeared, while still filtering.
- `--top N` on `otacon scan`, capping the table at the riskiest rows and saying how many it hid.
- ctrl+p lists the tool's own commands instead of only Textual's.
- Scan reports now carry `dns_queries` and `dns_failures`, and the terminal verdict refuses to say "All clear" when failures reach 20% of lookups — it reports the scan as inconclusive instead. A domain that does not exist and a domain that could not be checked produce the same empty result, which is how v2.0.0 shipped a confident all-clear while resolving nothing. A name that does not exist counts as an answer rather than a failure, so a healthy scan sits near 5% even though most variants are unregistered.
- A scheduled `Live network tests` workflow runs `pytest -m network` weekly and asserts that a real scan of a heavily squatted brand still returns registered lookalikes. The suite excludes that marker by default, so those tests had never run in CI — the guard against the aiodns class of break was dormant.

### Changed
- The brand mark is monochrome. The gradient was the only thing competing with severity for the reader's eye, and below truecolor its four stops quantised to one flat colour, so the wordmark looked broken rather than plainer on a 16-colour terminal. The Cyrillic homoglyph is now picked out by weight, which survives `mono`, `NO_COLOR`, greyscale and paper. Two rows of dots became one travelling pulse in the density ramp the rest of the interface uses.
- `otacon scan` prints one line per finding. Badges, technique, reasons and the page title all lived inside a column two dozen characters wide and wrapped across three lines each, so twelve findings filled a screen and a half. Reasons moved below the table, where prose has the width of the terminal.
- The triage console's risk column is one density glyph rather than an eight-cell bar. Stacked down a real scan, whose scores inside a band rarely differ by enough to change a bar's length, it painted one uniform block and separated nothing while costing the width `FLAGS` needed.
- Both tables name each severity run where it starts, so where "act now" ends is visible rather than inferred.
- One spelling per finding across every surface. The same flag was `[cloned-favicon]` in the scan output, `FAVICON` in the triage console and `cloned favicon` in the HTML report.
- The masthead tally is labelled. It was five bare glyphs and five numbers with no legend anywhere on screen.
- The HTML report follows the active theme, including its chart colours, which were a fifth copy of the palette.

### Removed
- The gradient machinery — `Palette.gradient`, `caps.gradient_stops`, `emit.gradient_color`, `GRADIENT` and `gradient()`. With the mark monochrome it drew nothing.
- **Breaking:** `otacon.utils` no longer re-exports `GRADIENT`, `gradient`, `gradient_color`, `LOGO_DOTS_TOP` or `LOGO_DOTS_BOT`.
- The `»` defensive marker. It rode in the domain cell beside the redirect host, wrapped the column, and needed a footnote to explain a glyph that said less than the word `OURS` now in the flags column.
- `_redirect_host`, which turned out to be duplicated inline in the HTML reporter; both reporters now call one helper in `utils.validate`.
- **Breaking:** deleted the questionary guided mode. The triage console is the default surface and carries every action it had, so the prompts were a second way to do the same thing — and the one that forced 25 `sys.modules` lookups into production code so tests could reach past it. `triage/workflow.py`, `triage/prompts.py`, `interactive.py`, most of `triage/actions.py` and 935 lines of tests are gone, about 1,700 lines in all. Running `otacon` where Textual cannot start now says to use `otacon scan <domain>` instead of failing obscurely.
- Deleted the last two `sys.modules` searches that let production code discover test doubles: `engine.scanner`'s generator lookup (it now imports the permutations module rather than the function, so patching the module is simply seen) and `cli.commands.scan`'s `_get_cli`. Repointing the tests at the modules that hold the code revealed that one of them had stopped taking effect and was running a real network scan — the suite now finishes in 15 seconds rather than 53.
- Dropped `questionary` and `prompt_toolkit` from the dependencies; nothing imports them any more.
- Deleted seven re-export shims left over from the 2.0 restructure — `_hashutils`, `_scanner`, `_validate`, `html_report`, `models`, `resolver` and `theme`. They forwarded pre-2.0 import paths that no published release ever used: 2.0.0 was never published and 1.0.x had a different layout entirely. Every importer now names the module that holds the code.
- Deleted `engine.scanner`'s `sys.modules` search for a patched `Resolver`, and the two remaining lookups in `net/tls.py` and `net/resolver.py` that scanned for overrides on the shim module just deleted — dead branches that could never fire again. Production code no longer inspects the import table to discover test doubles in those paths.
- Deleted `uv.lock` and `docs/specs/`. The lockfile was a second, unreferenced dependency pin alongside the hash-pinned `requirements*.txt` that CI actually installs, free to drift from it; the spec described a feature that shipped.

### Fixed
- `critical` was the only style with a background, so an age cell or a badge rendered as a red block inside the table and read as a rendering fault rather than as emphasis.
- Rebuilding the findings table sent the cursor back to row one, throwing an operator to the top every time a WHOIS answer or a re-check landed.
- The dossier lost its label/value alignment on long values — IP lists, redirect URLs — wrapping them back to column zero on exactly the rows carrying the most evidence.
- Glyph support was probed from `sys.stdout` at render time, which Textual replaces when it starts, so the interface answered one way before running and another way once running. It is resolved once, from the real terminal.
- The brand mark degraded its sweep and its arrow for `--ascii` but not its letters, showing a replacement character inside the mark itself.
- `#statusbar` and `#filterbar` had a border on a one-row box, leaving nowhere to draw their text.
- The test suite wrote scan history into the developer's own `~/.otacon`. Several tests run the real `execute_scan`, which persists its report, so fixture domains like `evil-twin.com`, `clean.com` and `a.com` accumulated in a real user directory. An autouse fixture in `tests/conftest.py` now points `OTACON_HOME` at a temporary directory for every test, with a test asserting it holds.

## [2.1.0] — 2026-10-28

The last version published to PyPI was 1.0.3, so this release carries both the
2.0 modular rewrite and everything since. 2.0.0 was committed but never tagged
or published, so upgrading from 1.0.x lands here directly.

Two changes alter results rather than interfaces. Risk scores are rebalanced,
so stored baselines will differ and `--fail-on` gates may reach a different
verdict — both because scoring changed and because DNS detection was broken
before and now works. Importing `otacon.whois` is no longer possible; the same
functions live in `otacon.net.whois`.

### Added
- Certificate Transparency (CT) log discovery via Certspotter API with graceful crt.sh fallback to discover certificates issued in the wild, with `--no-ct` CLI flag.
- Deep Email Security inspection: SPF and DMARC policy analysis; identifies active email spoofing / BEC vectors (+15 pts) when MX is present without strict DMARC enforcement (`p=quarantine` or `p=reject`).
- Continuous monitoring comparison engine and CLI command: `otacon diff <file1.json> <file2.json>` to track domain modifications, new registrations, mail activation, and dropped domains with optional `--fail-on-threats` CI gating.
- Favicon MurmurHash3 (Shodan/Censys standard) fingerprinting in pure-Python (`mmh3_32`) to detect cloned visual brand assets.
- Credential harvesting / login form heuristic detection (`<input type="password">` / auth fields).
- Advanced domain parking classifier detecting parking nameservers (Sedo, Bodis, Dan.com, Afternic, Parkingcrew) and parking IP subnets.
- Law-enforcement and CERT sinkhole classifier (Shadowserver, cert.pl, FBI seizure) to neutralize false-alarm scoring on seized domains.
- Passive DNSBL threat intelligence integration (Spamhaus DBL and SURBL) via non-blocking async DNS queries with `--no-dnsbl` CLI flag.
- Visual badges in terminal tables and HTML reports (`[DBL listed]`, `[cloned favicon]`, `[login form]`, `[spoofable mail]`, `[parked]`, `[sinkhole]`).
- `--no-whois` CLI flag to bypass WHOIS / RDAP lookups, preventing registry rate-limits and IP blocking during high-volume scans.
- European ccTLDs (`.pl`, `.de`, `.uk`, `.eu`, `.fr`) to `_ALT_TLDS` mutation table.
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

### Added
- README section covering the signals Otacon actually gathers — mail security, TLS, brand cloning, credential capture, DNSBL reputation, Certificate Transparency discovery and registration data. All of these shipped in v2.0 and none of them was mentioned on the landing page.
- `tools/render_tui_svg.py`, the companion to `render_demo_svg.py`, so the triage-console screenshot in the README is reproducible from a real scan rather than a mock-up.
- `otacon tui [domain]` — a keyboard-driven triage console built on Textual. A scan produces a few hundred rows of which a handful matter; the console keeps the whole report in memory and lets one hand work it. Arrows or `j`/`k` move, `1`–`5` filter to a single risk level, `/` filters by substring, `a` reveals unregistered variants, and `w` / `t` / `e` run WHOIS, render the abuse notice, and export the selected row. The dossier pane on the left tracks the cursor, showing every signal with its plain-language meaning and the full scoring breakdown.
- `otacon tui --from <report.json>` reopens a saved report with no network traffic at all, so a nightly CI scan can be triaged by hand the next morning.
- `triage/notice.py` with `build_takedown_notice()`, extracted from the questionary handler so the console and the guided mode render the same notice from one source, and so the text can be asserted without driving a prompt.
- Network-marked regression tests (`pytest -m network`) that resolve against real DNS and assert a scan of a heavily squatted brand returns registered lookalikes. Their absence is what let the aiodns 4 break ship.

### Removed
- Deleted four unreachable compatibility shims: `cli.py`, `scoring.py`, `reporters.py` and `permutations.py`. Each was shadowed by a package of the same name, so Python resolved every `otacon.cli` / `otacon.scoring` / `otacon.reporters` / `otacon.permutations` import to the package and none of these files was ever imported. The backwards compatibility they documented did not exist.
- Collapsed `theme.py`, `_validate.py` and `whois.py` from full second copies into thin re-exports of `utils/theme.py`, `utils/validate.py` and `net/whois.py`. The palette, the trust-boundary validators and the WHOIS/RDAP client each existed twice, so a change had to be made in two places to take effect everywhere.

### Changed
- Widened the triage console's results table to two thirds of the window. Its columns are fixed-width and `FLAGS` — the column that changes what an operator does with a row — was clipped to four characters at the previous ratio; the dossier reflows instead.
- Corrected the README's claimed Python support from 3.11–3.13 to 3.12–3.13. 3.11 was never able to build the package.
- The `SAFE_GLYPHS` guard in `tests/test_theme.py` now checks the modules that actually render — `reporters/console.py`, `cli/`, `triage/`, `engine/scanner.py` — instead of the legacy shim files `reporters.py` and `cli.py`, two of which were unreachable dead code.
- Rebalanced risk scoring to separate impersonation evidence from infrastructure capacity. Resolving, answering HTTP, holding a certificate and accepting mail summed to roughly +85 raw — which is simply what a working website looks like — so any live domain scored critical on its own. Their combined contribution is now capped (`infra_cap`, default 35, overridable via `--weights-file`) and the reason list reports when the cap binds. On `github.com` this cut critical findings from 60 to 2, both of which are genuine (one with a cloned title and favicon, one listed on Spamhaus DBL).
- Domain age can now reduce a score instead of only raising it: ≥2 years scores −15 and ≥5 years scores −30. A lookalike registered years ago and never used in a campaign is usually an unrelated business, not a live threat. Scores are floored at 0.
- The fresh-certificate boost is now gated on the domain itself being under 90 days old. Let's Encrypt renews every 60 days, so a days-old certificate was firing on healthy sites across the web.

### Fixed
- Fixed Otacon being unusable on Windows. `engine/pool.py` imported the Unix-only `resource` module at module level, raising `ModuleNotFoundError` on import; `engine/scanner.py` imports `ResourceLimiter` from it, so the failure propagated to the entire CLI. The import is now guarded by `sys.platform`, and the Windows path returns the requested concurrency unchanged since Windows exposes no per-process descriptor ceiling to query. This also clears the `mypy --strict` failures that had the three `windows-latest` CI legs red.
- Subdomains of the scan target discovered through Certificate Transparency are no longer added as permutations. CT aggregators are queried with `include_subdomains`, so most hits are the target's own infrastructure; scoring them as lookalikes made the target's own subdomains the single largest source of critical findings (29 of 77 high/critical results on `github.com`).
- Replaced the `sys.modules` inspection in `get_age_fresh_days()` / `get_age_new_days()` with a direct read. The previous implementation treated the default value as a sentinel, so explicitly setting `AGE_FRESH_DAYS = 7` or `AGE_NEW_DAYS = 30` was silently ignored.
- Fixed total loss of DNS detection under the pinned `aiodns==4.0.4`: aiodns 4 replaced `query()` with `query_dns()` and changed the return type from a flat list of records exposing `.host`/`.text` to a `DNSResult` whose `.answer` holds `DNSRecord`s with typed `.data` payloads. Iterating a `DNSResult` raises `TypeError`, which every call site's graceful-degradation handler swallowed, so A, AAAA, MX, NS, TXT and DNSBL lookups all returned empty and every scanned domain was reported as unregistered. Both record shapes are now normalised in a single adapter (`net.dns.query_records`), replacing three duplicate copies of the dispatch helper.
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
