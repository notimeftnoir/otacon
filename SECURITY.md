# Security Policy

## Scope

Otacon is a **passive reconnaissance tool** — it issues standard DNS queries, a single TLS handshake, and one HTTP GET per variant domain. It does not exploit any vulnerability, write to remote systems, or perform any action on the domains it probes.

Please report security issues related to:

- Vulnerabilities in Otacon's own code (e.g. path traversal, injection, unsafe deserialization)
- Dependency vulnerabilities with a direct, practical exploit path against Otacon users
- Logic flaws that could cause the tool to behave in a way that harms the operator's own systems

Out of scope:

- Denial-of-service against Otacon itself
- Rate-limiting or resource exhaustion
- Theoretical issues with no practical exploit path
- Issues in dependencies not affecting Otacon users directly

## Reporting

Please **do not open a public GitHub issue** for security vulnerabilities.

Report privately by emailing **gabriel.bieszczad@gmail.com** with:

1. A clear description of the vulnerability
2. Steps to reproduce or a proof-of-concept
3. The potential impact

You will receive a response within **72 hours**. Confirmed vulnerabilities will be patched and credited (unless you prefer to remain anonymous).

## Supported Versions

Only the latest release on `main` is actively maintained. Please verify the issue exists on the current version before reporting.

## Ethical Use

Otacon performs passive DNS/HTTP checks identical to what any browser does when loading a webpage. Use it only on domains you own or have explicit written permission to monitor. Misuse is your sole responsibility.

## Hardening posture

Otacon assumes the targets it probes are **hostile** — the whole point is that a typosquat is suspicious. The runtime is hardened on that assumption:

- **SSRF guard on lookalike probing.** Every A/AAAA answer for a scanned variant is vetted (`first_safe_ip`) against RFC 1918 / loopback / link-local / multicast / reserved / cloud-metadata ranges before the HTTP/TLS probe connects — a mixed public+internal DNS answer poisons the whole batch rather than "picking the good IP". The resulting TCP connect is pinned to that safe IP via a custom `httpcore.AsyncNetworkBackend`, closing the DNS-rebinding window between the check and the actual connect. SNI / `Host` header still derive from the original hostname, so legitimate TLS verification works.
- **Path-traversal guard on every file output** (`--json`, `--markdown`, `--csv`, `--html`, `--output`, interactive export). `safe_relative_path` confines writes to CWD and rejects NUL bytes, drive letters, Windows reserved device names and `..` escapes after canonicalisation.
- **HTTP body cap.** Probes stream the response and break at 64 KiB to defeat decompression-bomb fakes; the connection pool is bounded to the scan concurrency via `httpx.Limits`.
- **Hard wall-clock deadline (15 s)** per probe — defeats slow-loris hostile lookalikes.
- **TLS probing uses `CERT_NONE`** intentionally so we can inspect bad certs; the body is only used to extract `<title>` (capped at 80 chars), never trusted for anything else.
- **No `pickle` / `yaml.load` / `eval` / `exec`** anywhere in the source tree. JSON via `pydantic.model_validate_json` is the only deserialiser.
- **HTML report** ships `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none';` and `<meta name="referrer" content="no-referrer">`. All interpolations route through `html.escape`.
- **Terminal output** wraps external strings (paths, OS errors, DNS hostnames) in `rich.markup.escape()` to prevent markup-injection.
- **CSV export is formula-injection-safe** (CWE-1236): any attacker-controlled cell (page title, redirect target) starting with `=`, `+`, `-` or `@` — optionally after whitespace — is prefixed with an apostrophe so spreadsheet apps read it as text, not a formula.

## Supply-chain posture

- **PyPI release** uses [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC, no long-lived API token), in a protected `pypi` environment with least-privilege `permissions:`.
- **Release artefacts** are keyless-signed with [Sigstore](https://docs.sigstore.dev/) and a CycloneDX SBOM is generated per build.
- **All GitHub Actions are SHA-pinned** (first-party `actions/*` and third-party `sigstore/*`, `pypa/*`) — tag mutations cannot rewrite CI.
- **CodeQL** runs `security-extended` + `security-and-quality` queries on every push and weekly.
- **Dependabot** is enabled for both `pip` and `github-actions` (weekly).
- Production dependencies are exact-pinned in `requirements.txt`; CI runs `pip-audit` on every push.
