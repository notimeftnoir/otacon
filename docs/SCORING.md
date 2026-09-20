# How scoring works

_[← back to the README](../README.md)_ · [Usage](USAGE.md) · [Scoring](SCORING.md) · [Output](OUTPUT.md) · [CI/CD](CI.md) · [FAQ](FAQ.md) · [Design](DESIGN.md)

---

Every score is the sum of **explicit, explainable signals** — no ML, no black box. Every reason is exposed in the JSON export (`risk_reasons`) and in the interactive detail view.

<details open>
<summary><b>Signal point values</b></summary>

| Signal | Points |
|---|---|
| **MX record** — ready for email phishing | +25 |
| **Technique** — homoglyph / IDN | +25 |
| &nbsp;&nbsp;subdomain spoof | +22 |
| &nbsp;&nbsp;combosquat · www-merge | +20 / +20 |
| &nbsp;&nbsp;typo | +18 |
| &nbsp;&nbsp;soundsquat | +16 |
| &nbsp;&nbsp;bitsquat · vowel-swap | +15 / +14 |
| &nbsp;&nbsp;hyphenation · plural · TLD-swap | +12 / +10 / +10 |
| **Domain age** — &lt;7 days | +20 |
| &nbsp;&nbsp;&lt;30 days · &lt;90 days | +12 / +5 |
| **SSL** certificate active | +15 |
| **HTTP** 2xx live · 3xx redirect | +15 / +10 |
| &nbsp;&nbsp;4xx · 5xx | +5 / +3 |
| **Resolves** to an IP | +10 |
| **Redirects** elsewhere (non-2xx, non-3xx) | +5 |

Score is capped at 100. Unregistered domains always score 0.

</details>

### Risk levels

| Level | Score | Meaning |
|---|---|---|
| 🔴 **critical** | 80–100 | Active infrastructure + email-ready — treat as a live threat. Investigate immediately. |
| 🟠 **high** | 60–79 | Registered with serious signals (MX or live site). Add to monitoring; consider takedown. |
| 🟡 **medium** | 35–59 | Registered, some signals — worth watching. |
| 🔵 **low** | 15–34 | Registered, minimal signals. Could be parked / unused. |
| 🟢 **safe** | 0–14 | Unregistered or negligible. |

> 📐 Full architecture, pipeline, and design rationale → [`DESIGN.md`](DESIGN.md)

---
