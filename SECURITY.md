# Security Policy

## Supported versions

Security fixes are released for the latest `1.0.x` line. Older patch releases
are not maintained — please reproduce any issue on the most recent release
before reporting.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Scope

Otacon is a **passive reconnaissance tool** — it issues standard DNS queries, a single TLS handshake, and one HTTP GET per variant domain. It does not exploit any vulnerability, write to remote systems, or perform any action on the domains it probes.

In scope:

- Vulnerabilities in Otacon's own code (e.g. path traversal, injection, unsafe deserialization)
- Dependency vulnerabilities with a direct, practical exploit path against Otacon users
- Logic flaws that could cause the tool to behave in a way that harms the operator's own systems (e.g. an SSRF or path-traversal escape)
- **Resource exhaustion of the Otacon process triggered by a hostile scanned host** — e.g. a decompression bomb, a slow-loris response, or an oversized body. Otacon defends against these (see *Hardening posture*), so a working bypass of those defences is a valid report.

Out of scope:

- Denial-of-service a local user inflicts on their own machine (e.g. deliberately scanning an enormous permutation set)
- Rate-limiting of Otacon's own outbound probes
- Theoretical issues with no practical exploit path
- Issues in dependencies that do not affect Otacon users directly

## Reporting a vulnerability

Please **do not open a public GitHub issue** for security vulnerabilities.

Report privately through **[GitHub Private Vulnerability Reporting](https://github.com/notimeftnoir/otacon/security/advisories/new)** — the *Report a vulnerability* button on the repository's **Security** tab. This keeps the report, the fix, and any CVE coordination in a single private thread.

Please include:

1. A clear description of the vulnerability
2. Steps to reproduce or a proof-of-concept
3. The potential impact

### What to expect

Otacon is maintained by one person on a best-effort basis:

- **Acknowledgement** within **7 days**.
- **Initial assessment** within **14 days** — confirmed, needs more information, or out of scope.
- **Coordinated disclosure** up to **90 days** from acknowledgement. The goal is a fix plus a published GitHub Security Advisory (with a CVE where warranted) before that window closes; if a fix genuinely needs longer, we'll agree a timeline with you rather than disclose unfixed.
- **Credit**: confirmed reporters are credited in the advisory and release notes, unless you ask to remain anonymous.

Maintainer: **Gabriel Bieszczad ([@notimeftnoir](https://github.com/notimeftnoir))**.

## Safe harbor

We will not pursue or support legal action against anyone who, in good faith, discovers and reports a vulnerability in Otacon's own code through the process above, provided they:

- make a genuine effort to avoid privacy violations, data destruction, and disruption to others;
- only probe domains and systems they own or are explicitly authorised to test — Otacon is itself a reconnaissance tool, and researching *Otacon* does not authorise scanning anyone else;
- give us reasonable time to remediate before any public disclosure.

Activity conducted consistently with this policy is considered authorised. If you are unsure whether something is in scope, ask first — we're happy to clarify before you start.

## Ethical use

Otacon performs passive DNS/HTTP checks identical to what any browser does when loading a webpage. Use it only on domains you own or have explicit written permission to monitor. Misuse is your sole responsibility.

## Hardening posture

Otacon assumes the targets it probes are **hostile** — the whole point is that a typosquat is suspicious. The runtime is hardened on that assumption:

- **SSRF guard on lookalike probing.** Every A/AAAA answer for a scanned variant is vetted (`first_safe_ip`) against RFC 1918 / loopback / link-local / multicast / reserved / cloud-metadata ranges before the HTTP/TLS probe connects — a mixed public+internal DNS answer poisons the whole batch rather than "picking the good IP". The resulting TCP connect is pinned to that safe IP via a custom `httpcore.AsyncNetworkBackend`, closing the DNS-rebinding window between the check and the actual connect. SNI / `Host` header still derive from the original hostname, so legitimate TLS verification works.
- **Path-traversal guard on every file output** (`--json`, `--markdown`, `--csv`, `--html`, `--output`, interactive export). `safe_relative_path` confines writes to CWD and rejects NUL bytes, drive letters, Windows reserved device names and `..` escapes after canonicalisation.
- **HTTP body cap.** Probes stream the response and break at 64 KiB to defeat decompression-bomb fakes; the connection pool is bounded to the scan concurrency via `httpx.Limits`.
- **Hard wall-clock deadline (15 s)** per probe — defeats slow-loris hostile lookalikes.
- **TLS probing uses `CERT_NONE`** intentionally so we can inspect bad certs; the body is only used to extract `<title>` (capped at 80 chars), never trusted for anything else.
- **No `pickle` / `yaml.load` / `eval` / `exec`** anywhere in the source tree. The only JSON parsing is the standard-library `json.loads` (e.g. the `--weights-file` input), never a code-executing deserialiser.
- **HTML report** ships `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none';` and `<meta name="referrer" content="no-referrer">`. All interpolations route through `html.escape`.
- **Terminal output** wraps external strings (paths, OS errors, DNS hostnames) in `rich.markup.escape()` to prevent markup-injection.
- **CSV export is formula-injection-safe** (CWE-1236): any attacker-controlled cell (page title, redirect target) starting with `=`, `+`, `-` or `@` — optionally after whitespace — is prefixed with an apostrophe so spreadsheet apps read it as text, not a formula.

## Supply-chain posture

- **PyPI release** uses [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC, no long-lived API token), in a protected `pypi` environment with least-privilege `permissions:`.
- **Release artefacts** are keyless-signed with [Sigstore](https://docs.sigstore.dev/). A CycloneDX SBOM is generated in CI on every build.
- **All GitHub Actions are SHA-pinned** (first-party `actions/*` and third-party `sigstore/*`, `pypa/*`) — tag mutations cannot rewrite CI.
- **CodeQL** runs `security-extended` + `security-and-quality` queries on every push and weekly.
- **Dependabot** is enabled for `pip`, `github-actions` and `pre-commit` (weekly, grouped into one PR per ecosystem).
- Production dependencies are hash-pinned with `--require-hashes` in `requirements*.txt` (compiled from `.in` sources); CI runs `pip-audit` on every push.
