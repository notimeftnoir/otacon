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

Because pentesters and SOC analysts need to *defend* their findings. "Our model gave it 87" is not a defensible answer. `risk_reasons` is. Every score in Otacon comes with the exact list of signals that produced it — auditable in five seconds, tunable in a one-line edit to `scoring.py`.

</details>

<details>
<summary><b>How fast is it?</b></summary>

A full scan with HTTP probing on a 150-permutation domain typically completes in **8–15 seconds** on a residential connection. DNS-only mode (`--no-http`) is roughly **3× faster**.

Bottlenecks are usually:
1. WHOIS query rate-limiting (we cap at 4 concurrent)
2. DNS resolver latency (default `--concurrency 50` is conservative; raise it on a server with a fast resolver)
3. The `c-ares` library — make sure it's installed natively, not falling back to Python's stdlib resolver

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
2. **They're behind Cloudflare / a CDN** — they resolve but the SSL/HTTP probe times out. Increasing `--concurrency` doesn't help; raise the per-request timeout in `resolver.py` if it's a recurring issue.
3. **Your DNS resolver is rate-limiting** — try with a different resolver or lower `--concurrency`.
4. **The fakes are on a TLD not in our default list** — open an issue with the TLD.

</details>

<details>
<summary><b>Where is the WHOIS data coming from?</b></summary>

We use [`asyncwhois`](https://pypi.org/project/asyncwhois/), which talks directly to TLD WHOIS servers (no third-party API, no quota). Some TLDs (e.g., `.ai`, `.io`) sometimes return rate-limited or stripped responses — in that case `age_days` will be `null` and the age-based scoring contribution is just skipped (graceful degradation).

</details>

<details>
<summary><b>How do I add my own permutation technique?</b></summary>

1. Add a value to the `PermutationType` enum in `models.py`
2. Add a `_my_technique(label: str) -> set[str]` function in `permutations.py`
3. Add it to the pipeline list in `generate()` — order matters for dedup priority
4. Add a base score in `scoring._KIND_BASE`
5. Open a PR with tests in `tests/test_permutations.py`

</details>

---

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ModuleNotFoundError: aiodns` on install | `c-ares` system library missing | `apt install libc-ares-dev` / `brew install c-ares`, then reinstall |
| Scan hangs at "Checking variants" | DNS resolver unreachable or rate-limiting | Lower `--concurrency`, switch resolver (`1.1.1.1`, `8.8.8.8`) |
| WHOIS always `—` for `.ai` / `.io` / `.pl` | Registry WHOIS rate-limit | Re-run later; this is normal |
| Windows: `ConnectionResetError [WinError 10054]` | Should be auto-fixed in 1.0+ | Ensure you're on the latest version; this used the Proactor loop, we've switched to Selector on Windows |
| `Unverified HTTPS request` warnings | Suppressed intentionally — we probe bad certs on purpose | n/a, hidden by default |

If something still doesn't work, please [open an issue](https://github.com/notimeftnoir/otacon/issues) with:

- Otacon version (`otacon --version`)
- Python version, OS, and architecture
- The full command and (if safe to share) the target
- The error message or unexpected behavior

---
