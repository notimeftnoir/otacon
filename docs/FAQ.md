# FAQ & troubleshooting

_[← back to the README](../README.md)_ · [Usage](USAGE.md) · [Scoring](SCORING.md) · [Output](OUTPUT.md) · [CI/CD](CI.md) · [FAQ](FAQ.md) · [Design](DESIGN.md)

---

<details>
<summary><b>Is this legal? Does it touch the target domains?</b></summary>

Otacon performs only **passive recon**: standard DNS queries, a TLS handshake on :443 (no data exchange), and a single HTTP GET. No login attempts, no scanning, no scraping at scale. This is the same level of activity as visiting the page in a browser.

That said, use it on **your own domains** or **within authorized engagements**. See `LICENSE` and `SECURITY.md`.

</details>

<details>
<summary><b>Why no machine learning?</b></summary>

Because pentesters and SOC analysts need to *defend* their findings. "Our model gave it 87" is not a defensible answer. `risk_reasons` is. Every score in Otacon comes with the exact list of signals that produced it — auditable in five seconds, tunable with a `--weights-file`, or a one-line edit to `scoring/config.py`.

</details>

<details>
<summary><b>How fast is it?</b></summary>

A full scan of a typical domain (~230 permutations) with HTTP probing takes **30–60 seconds** on a residential connection; the more variants are registered, the longer the TLS/HTTP/WHOIS phase. DNS-only mode (`--no-http`) is roughly **3× faster** — about 12 seconds for `example.com`.

Bottlenecks are usually:
1. WHOIS query rate-limiting (we cap at 4 concurrent)
2. DNS resolver latency (default `--concurrency 50` is conservative; raise it on a server with a fast resolver)
3. TLS + HTTP probing of every live variant — `--no-http` skips it when you only need DNS/MX/WHOIS

</details>

<details>
<summary><b>Will it find IDN homoglyph attacks (xn-- domains)?</b></summary>

Yes. The `IDN` technique generates punycode-encoded variants for each Unicode homoglyph. They show up as `xn--...` in the table. Score base is +25, same as homoglyph — these are the most dangerous because they render as the original glyph in most browsers.

</details>

<details>
<summary><b>Does it work on internationalized domains (non-ASCII targets)?</b></summary>

Partially. Otacon accepts unicode input but the permutation engine is tuned for ASCII labels. IDN/punycode encoding works for *output* (generated homoglyphs of an ASCII original). True i18n of the engine is on the roadmap.

</details>

<details>
<summary><b>Why does my scan show 0 results when I know there are fakes?</b></summary>

Most likely causes, in order:

1. **DNS-only mode missed them** — with `--no-http`, you only see variants that resolve. Try a full scan.
2. **They're behind Cloudflare / a CDN** — they resolve but the SSL/HTTP probe times out. Increasing `--concurrency` doesn't help; raise the per-request timeout in `net/http.py` if it's a recurring issue.
3. **Your DNS resolver is rate-limiting** — try with a different resolver or lower `--concurrency`.
4. **The fakes are on a TLD not in our default list** — open an issue with the TLD.

</details>

<details>
<summary><b>Where is the WHOIS / registration data coming from?</b></summary>

Otacon first queries modern **RDAP (Registration Data Access Protocol)** over HTTPS via `rdap.org` using `httpx`. RDAP avoids corporate firewall blocks on TCP port 43. If an RDAP endpoint is unavailable or returns an error, Otacon gracefully falls back to traditional port 43 WHOIS via [`asyncwhois`](https://pypi.org/project/asyncwhois/). If both fail or rate-limit, `age_days` degrades gracefully to `null` without crashing the scan.

</details>

<details>
<summary><b>How do I add my own permutation technique?</b></summary>

1. Add a value to the `PermutationType` enum in `core/types.py`
2. Add a `rule_my_technique(label: str) -> set[str]` function in `permutations/rules.py`
3. Add it to the pipeline list in `generate()` — order matters for dedup priority
4. Add a base score in `ScoringWeights.kind_base` (`scoring/config.py`)
5. Open a PR with tests in `tests/test_permutations.py`

</details>

---

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Verdict says "Inconclusive: N% of DNS lookups failed" | The resolver could not answer, so an unregistered-looking domain may simply never have been checked | Re-run with `--debug` to see the errors. A captive portal, a blocked port 53, or an incompatible `aiodns` build are the usual causes |
| `pip` tries to compile `pycares` and fails | No prebuilt wheel for your Python/platform (wheels cover CPython 3.10–3.14 on Linux, macOS and Windows; PyPy or an unusual CPU architecture may lack one) | Use CPython 3.12–3.13, or install the `c-ares` headers (`apt install libc-ares-dev` / `brew install c-ares`) so it can build |
| Scan hangs at "Checking variants" | DNS resolver unreachable or rate-limiting | Lower `--concurrency`, switch resolver (`1.1.1.1`, `8.8.8.8`) |
| WHOIS always `—` for `.ai` / `.io` / `.pl` | Registry WHOIS rate-limit | Re-run later; this is normal |
| Windows: `ConnectionResetError [WinError 10054]` | Should be auto-fixed in 1.0+ | Ensure you're on the latest version; this used the Proactor loop, we've switched to Selector on Windows |

If something still doesn't work, please [open an issue](https://github.com/notimeftnoir/otacon/issues) with:

- Otacon version (`otacon --version`)
- Python version, OS, and architecture
- The full command and (if safe to share) the target
- The error message or unexpected behavior

---
