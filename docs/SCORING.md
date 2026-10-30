# How scoring works

_[← back to the README](../README.md)_ · [Usage](USAGE.md) · [Scoring](SCORING.md) · [Output](OUTPUT.md) · [CI/CD](CI.md) · [FAQ](FAQ.md) · [Design](DESIGN.md)

---

Every score is built from **explicit, explainable signals** — no ML, no black box. Every reason is exposed in the JSON export (`risk_reasons`) and in the interactive detail view.

Signals fall into three groups, and the distinction is what makes the score useful:

1. **Identity** — how closely the name imitates the target. Set by the permutation technique.
2. **Infrastructure** — whether the domain *could* host an attack. Capped, because every working website scores most of it.
3. **Evidence** — whether it actually *is* impersonating. This is what decides the verdict, and it is the only group that can argue a domain down.

<details open>
<summary><b>1. Identity — permutation technique</b></summary>

| Technique | Points |
|---|---|
| homoglyph · IDN | +25 |
| subdomain spoof | +22 |
| combosquat · www-merge · CT-log | +20 |
| typo | +18 |
| soundsquat | +16 |
| bitsquat | +15 |
| vowel-swap | +14 |
| hyphenation | +12 |
| plural · TLD-swap | +10 |

</details>

<details open>
<summary><b>2. Infrastructure — capped at +35 in total</b></summary>

| Signal | Points |
|---|---|
| **MX record** — ready for email phishing | +25 |
| **SSL** certificate active | +15 |
| &nbsp;&nbsp;certificate issued &lt;7 days ago, *on a domain under 90 days old* | +10 |
| &nbsp;&nbsp;certificate SAN does not cover the probed host | +5 |
| **HTTP** 2xx live · 3xx redirect | +15 / +10 |
| &nbsp;&nbsp;4xx · 5xx | +5 / +3 |
| **Resolves** to an IP | +10 |
| **Redirects** elsewhere (non-2xx, non-3xx) | +5 |
| Permissive or missing DMARC with MX present — spoofing vector | +15 |

Raw, these sum to roughly +85 — which is simply what a functioning website looks like. Summed
unchecked they made every live domain critical regardless of whether it imitated anything, so
their combined contribution is capped (`infra_cap`, default 35). When the cap binds, the reason
list says so and reports the raw total. The fresh-certificate boost is gated on the *domain*
being new, because Let's Encrypt renews every 60 days and a days-old certificate is the normal
state of the healthy web.

</details>

<details open>
<summary><b>3. Evidence — uncapped, and the only group that can reduce a score</b></summary>

| Signal | Points |
|---|---|
| Listed on **Spamhaus DBL / SURBL** — active threat | +50 |
| **Favicon** matches the target — cloned visual brand | +35 |
| **Page title** cloned or ≥0.5 similar to the target | +25 |
| **Login form** / credential input detected | +20 |
| **Domain age** &lt;7 days | +20 |
| &nbsp;&nbsp;&lt;30 days · &lt;90 days | +12 / +5 |
| &nbsp;&nbsp;≥2 years — established domain | **−15** |
| &nbsp;&nbsp;≥5 years — long-established, not a fresh campaign | **−30** |

A lookalike registered years ago and never used in a campaign is usually an unrelated business
or a dormant portfolio holding. Age is the only signal that argues downward, which is what keeps
a sixteen-year-old bitsquat out of the critical band.

</details>

### Classifier overrides

Three classifiers bypass the arithmetic entirely:

| Classifier | Effect |
|---|---|
| **Sinkhole** — law-enforcement seizure or CERT sinkhole nameservers | score forced to 0 |
| **Defensive registration** — redirects to the target and has no MX | score forced to 0 |
| **Parked** — parking nameservers, IPs, or for-sale page | HTTP/DNS signals ignored |

Certificate Transparency candidates are collapsed to the registered domain and must carry the
brand label. The target, its subdomains, and every domain that shares a certificate with the
target are dropped before scoring — those are the target's own infrastructure, not impersonation.

The final score is clamped to 0–100. Unregistered domains always score 0.

All weights, including `infra_cap` and the two negative age bands, are overridable through
`--weights-file` (see [`USAGE.md`](USAGE.md)).

### Risk levels

| Level | Score | Meaning |
|---|---|---|
| 🔴 **critical** | 80–100 | Hard evidence of impersonation — cloned branding, a credential form, or a threat-list listing. Investigate immediately. |
| 🟠 **high** | 60–79 | A close lookalike with live infrastructure and at least one piece of evidence. Consider takedown. |
| 🟡 **medium** | 35–59 | Registered and working, but nothing yet shows it imitates you. Worth watching. |
| 🔵 **low** | 15–34 | Registered with minimal signals, or long-established and probably unrelated. |
| 🟢 **safe** | 0–14 | Unregistered or negligible. |

> 📐 Full architecture, pipeline, and design rationale → [`DESIGN.md`](DESIGN.md)

---
