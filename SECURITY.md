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
