# Otacon — Interface Roadmap

_[← back to the README](../README.md)_ · [Usage](USAGE.md) · [Scoring](SCORING.md) · [Output](OUTPUT.md) · [Design](DESIGN.md)

---

This document plans the interface work: what the surfaces look like today, what
is wrong with them, and the sequence that turns them into something an operator
*and* a non-specialist can both use without a manual.

[`DESIGN.md`](DESIGN.md) explains why the engine is built the way it is. This
one covers only what the user sees.

---

## Table of contents

- [Where we are](#where-we-are)
- [The root problem](#the-root-problem)
- [Target architecture](#target-architecture)
- [Phase 0 — design tokens](#phase-0--design-tokens)
- [Phase 1 — hierarchy in the triage console](#phase-1--hierarchy-in-the-triage-console)
- [Phase 2 — the non-specialist path](#phase-2--the-non-specialist-path)
- [Phase 3 — the scan itself](#phase-3--the-scan-itself)
- [Phase 4 — operator features](#phase-4--operator-features)
- [Phase 5 — console surface](#phase-5--console-surface)
- [Phase 6 — HTML report](#phase-6--html-report)
- [Phase 7 — brand and assets](#phase-7--brand-and-assets)
- [Non-goals](#non-goals)
- [Sequencing](#sequencing)

---

## Where we are

Four surfaces render the same `ScanReport`:

| Surface | Entry | Renderer |
|---|---|---|
| Triage console | `otacon`, `otacon tui` | `tui/` — Textual |
| Scan output | `otacon scan` | `reporters/console.py` — Rich |
| Live scan | during `otacon scan` | `engine/scanner.py` + `build_live_table` |
| Shareable report | `--html` | `reporters/html.py` |

### What already works

- **The console adapts well.** Column widths are tuned so `FLAGS` — the column
  that changes what an operator does — survives a narrow terminal, and the
  dossier reflows instead. That behaviour is correct and stays.
- **The dossier is the right idea.** Evidence beside the row, with a plain
  sentence under every fact, is the feature that makes the tool explainable.
- **The OPSEC gate on `o`** (arm, warn, confirm) is a genuinely good detail.
- **The verdict card** in `otacon scan` answers "am I in trouble" in one line.
- **Scan history** is already persisted — several features below only need a
  screen on top of data that exists.

### What does not

Observed on a real scan of `example.com` (240 permutations; 0 critical,
2 high, 37 medium, 39 low, 5 safe):

**Hierarchy**

1. **The RISK column becomes a slab.** `████░░░░` per row, stacked over 30+
   rows whose scores all sit between 40 and 58, paints one uniform yellow
   block. It costs 8 columns and separates nothing.
2. **No severity grouping.** 37 medium rows look identical to each other and
   to the 2 high rows above them. Nothing marks where "act now" ends.
3. **The masthead tally is unlabelled glyphs.** `▌0 ▒2 ▒37 ▒39 ○5` — a
   newcomer cannot tell which number is critical.
4. **The dossier breaks its own alignment.** Long values (IP lists, redirect
   URLs) wrap to column 0 instead of hanging under the value column, so the
   label/value grid visibly falls apart on exactly the rows that matter most.
5. **The dossier wastes its lower half.** On a short evidence list, two-thirds
   of the pane is empty.

**Discoverability**

6. **No help screen.** Ten single-letter bindings in the footer, no `?`.
7. **No glossary.** `SPOOF`, `PARKED`, `DBL`, `ct-log`, `bitsquat` are never
   explained inside the UI.
8. **The score is unexplained.** `65/100` has no band legend and no "what this
   means" anywhere on screen.
9. **No next action per row.** `otacon scan` prints *Next steps*; the console —
   where the operator actually decides — prints nothing.
10. **Filter state is a toast.** It disappears after two seconds, so the active
    filter becomes invisible while it is still filtering.

**The scan**

11. **The console's progress is poorer than the CLI's.** `otacon scan` shows a
    live tally and a live table of hits; the console start screen shows a bare
    bar and `Checked 112 of 240`.
12. **No phases.** DNS, HTTP/TLS, WHOIS and CT have very different durations
    and the user is told nothing about which one is running.

**Colour and robustness**

13. **Three independent copies of the palette** — `utils/theme.py` (Rich),
    `tui/styles.py` (Textual CSS literals), `reporters/html.py` (CSS custom
    properties). `tests/test_tui.py` asserts two of them overlap; nothing ties
    in the third. Changing one colour means three edits.
14. **`critical` is the only token with a background** (`bold white on #870000`).
    Inside a table it renders as red blocks behind an age cell or a badge,
    which reads as a rendering fault rather than emphasis.
15. **The gradient wordmark assumes truecolor.** On a 256-colour `TERM` every
    letter collapses to the same cyan and the logo looks broken.
16. **Dark only.** No light theme, no colour-blind-safe ramp (red/green is the
    most common form of deficiency and is exactly our top/bottom pair), no
    documented `NO_COLOR` behaviour inside Textual.
17. **No ASCII fallback path.** `SAFE_GLYPHS` documents the font budget but
    nothing degrades to ASCII when the terminal cannot meet it.
18. **The neutrals are ad-hoc.** Eight greys chosen one at a time, not a scale,
    so the interface reads flat — one background, one hairline, no elevation.

**Consistency**

19. **Badge vocabulary diverges per surface:** `[cloned-favicon]` in the
    console, `FAVICON` in the triage console, `cloned favicon` in HTML.
20. **The HTML report sets `Courier New` on `body`.** It is the surface most
    likely to be forwarded to someone who has never heard of the tool, and it
    is the one that looks the least credible.

---

## The root problem

Everything in the colour and consistency group above is one defect wearing
different clothes: **there is no design system, only three hard-coded
palettes.** Every visual change costs three edits and drifts anyway, and no
surface can gain a theme, a colour-blind ramp or an ASCII mode without all of
them being rewritten.

So the token layer comes first. Nothing else in this document is worth doing
before it, and most of it becomes cheap afterwards.

---

## Target architecture

A new `src/otacon/ui/` package becomes the single source of visual truth. It is
pure — no I/O, no Rich/Textual imports in `tokens.py` itself — so it stays
testable and cannot acquire a dependency cycle with the renderers.

```
src/otacon/ui/
  tokens.py      Palette, RiskTone, the four themes. Pure data.
  caps.py        Terminal capability detection: colour depth, unicode level.
  emit.py        Palette -> Rich Theme / Textual CSS / HTML vars / SVG theme.
  glyphs.py      Glyph sets with an ASCII fallback for every symbol.
  copy.py        One label per concept, shared by all four surfaces.
```

```python
@dataclass(frozen=True)
class RiskTone:
    fg: str  # bar, score, gutter sigil
    wash: str  # subtle row tint for the selected row in this band
    sigil: str  # unicode marker
    ascii: str  # fallback marker
    label: str  # "Act now" / "Review" / "Monitor" / "Noted" / "Harmless"


@dataclass(frozen=True)
class Palette:
    name: str
    dark: bool
    # neutral scale, back to front
    bg: str
    surface: str
    raised: str
    line: str
    line_strong: str
    dim: str
    muted: str
    body: str
    strong: str
    # brand
    brand: str
    brand_dim: str
    accent: str
    risk: Mapping[RiskLevel, RiskTone]
```

Four themes ship:

| Theme | Use |
|---|---|
| `midnight` | default dark |
| `daylight` | light terminals and printed HTML |
| `vision` | colour-blind-safe — blue→amber ramp, never red/green alone |
| `mono` | no hue; severity carried by weight and glyph only |

Selection order: `--theme` → `OTACON_THEME` → `NO_COLOR` forces `mono` → default
`midnight`.

Emitters:

```python
rich_theme(p)      -> rich.theme.Theme          # reporters/console.py, CLI
textual_vars(p)    -> dict[str, str]            # App.get_css_variables()
html_vars(p)       -> str                       # reporters/html.py :root block
terminal_theme(p)  -> rich.terminal_theme.TerminalTheme   # tools/render_*_svg.py
```

Textual reads design tokens through `App.get_css_variables()`, so
`tui/styles.py` stops holding hex literals and references `$risk-critical`,
`$surface`, `$line` instead. The drift test in `tests/test_tui.py` is then
replaced by a stronger one: every surface is generated from the same `Palette`,
so they *cannot* drift, and the test asserts each theme defines every token.

**Capability detection** (`caps.py`) resolves two independent axes:

- colour: `truecolor | 256 | 16 | none` from `COLORTERM`, `TERM`, `NO_COLOR`
  and Rich's own `color_system`;
- glyphs: `full | safe | ascii` from stream encoding and `OTACON_ASCII`.

The brand gradient takes the colour depth as an argument and degrades to a
256-palette ramp, then to a single brand colour — so the wordmark never
collapses silently.

---

## Phase 0 — design tokens

**Status: done.**

**Goal:** one palette, four themes, two capability axes. No visible change on a
truecolor dark terminal — this phase is judged by the diff, not a screenshot.

- [x] `ui/tokens.py`, `ui/caps.py`, `ui/emit.py`, `ui/glyphs.py`, `ui/copy.py`
- [x] `utils/theme.py` becomes a thin re-export so nothing downstream breaks
- [x] `tui/styles.py` loses every hex literal; `OtaconTUI.get_css_variables()`
- [x] `reporters/html.py` `:root` generated from `html_vars()`
- [x] `--theme` on every command, `OTACON_THEME` env, `NO_COLOR` → `mono`
- [x] `--ascii` / `OTACON_ASCII` degrade path, wired to `SAFE_GLYPHS`
- [x] Fix `critical`: no background token; emphasis by hue and weight, with the
      background reserved for the verdict card where it is deliberate
- [x] Tests: every theme is complete; every surface renders from one palette;
      snapshot per theme × colour depth

**Acceptance:** `OTACON_THEME=vision otacon scan example.com` and
`OTACON_ASCII=1 TERM=xterm otacon tui --from r.json` both render correctly, and
no hex literal exists outside `ui/tokens.py`.

---

## Phase 1 — hierarchy in the triage console

**Status: done.**

**Goal:** a 240-row scan reads as "two things to act on, the rest is noise" in
one glance.

### Risk column

Replace the 8-cell bar with a 1-cell severity gutter plus the score. The bar
becomes a toggle (`b`) for people who want it back.

```
 ▌ 100  paypa1.com           typo         3d   DNS MX SSL 200   DBL FAVICON LOGIN
 ▌  87  paypal-secure.com    combosquat  26d   DNS MX SSL 200   LOGIN SPOOF
────── HIGH · 2 ──────────────────────────────────────────────────────────────
 ▌  65  exampke.com          typo        21d   DNS ·· SSL 302
```

- Seven columns of width reclaimed, handed to `DOMAIN` and `FLAGS`.
- The gutter is one crisp edge per row instead of a 30-row slab.
- Severity separator rows give the eye the breakpoints the scores do not.

### Focus mode

`f` dims every row below the active threshold to the `dim` neutral. The top of
the list stops competing with 39 low rows for attention.

### Masthead

```
OTACON › example.com                 CRIT 0   HIGH 2   MED 37   LOW 39   OK 5     240 checked · 23s
```

Labels, not bare glyphs. The tally counts up on mount — the one piece of motion
that earns its place, because it tells you the numbers are freshly computed.

### Dossier

- Render as a `Table.grid` with a fixed label column and a folding value
  column, which fixes the wrap-to-column-0 bug on IPs and redirect URLs.
- Fill the dead lower half with: the score band explained in one sentence, the
  three actions available for *this* row, and the row's position in the scan.
- Section labels get a hairline rule rather than bare bold text.

### Status bar

A persistent line above the footer replaces the transient toasts:

```
filter HIGH+ · 39 of 240 shown · 2 selected · sorted by score · scanned 23s ago
```

**Acceptance:** a screenshot at 150×40 of a 240-row scan where the two high
rows are findable without reading any number.

---

## Phase 2 — the non-specialist path

**Status: done.**

**Goal:** someone who has never run a security tool can open the console, read
one screen, and know what to do.

- [x] **`?` help overlay** — bindings grouped by purpose, each with a sentence
      rather than a verb. *(landed with Phase 1)*
- [x] **Glossary** — every flag and every technique in one plain sentence,
      inside the help overlay. The bare `»` is now `OURS`. *(Phase 1)*
- [x] **Score bands on screen** — the five bands, their ranges and what each
      means for the reader. *(Phase 1)*
- [x] **One label per concept** — `ui/copy.py`, so no surface invents its own
      spelling. *(Phase 0)* Wiring the console and HTML to it is Phase 5/6.
- [x] **Scan presets on the start screen** — *Quick* (DNS only, ~10s),
      *Standard* (default), *Deep* (everything + CT), with the four checkboxes
      behind an *Advanced* disclosure instead of facing a first-time user.
- [x] **An overview screen after a scan** — verdict, distribution, the top
      three things to do, and the change since the previous scan of this target
      (history already stores it). `enter` opens the table.

**Acceptance:** a reader who knows nothing about DNS can state, from the
overview screen alone, how many domains need action and what the first one is.

---

## Phase 3 — the scan itself

**Status: done.**

**Goal:** the most interesting 30 seconds stop being a bar.

- [x] **Phase indicator.** Written here as `permutations → DNS → HTTP/TLS →
      WHOIS → CT`, which turned out not to be how the pipeline works: those
      checks all happen together inside one per-domain probe and are not
      stages at all. The real ones are building the list, discovering more
      from Certificate Transparency, and checking — and the middle one was
      the invisible wait worth fixing.
- [x] **Live findings feed** — hits appear as they are scored, worst first,
      exactly as `build_live_table` already does for `otacon scan`. Removes the
      regression where the CLI shows more than the console.
- [x] **Live tally** — the masthead counters fill during the scan.
- [x] **Cancel** — `esc` stops the scan and keeps the partial report; a scan
      that cannot be interrupted is a scan people run less often.
- [x] **Honest degradation** — the DNS-failure warning already in `ScanReport`
      surfaces *during* the scan, not only in the verdict.

---

## Phase 4 — operator features

**Goal:** the things an analyst asks for on day two.

- [ ] **Column sort** — `s` cycles score / domain / age / technique.
- [ ] **Multi-select** — `space` marks rows; `A` select-all-visible.
- [ ] **Bulk actions** — export, takedown notices and allow applied to a
      selection, with a confirm screen that names the count.
- [ ] **Persistent allow-list** — `a` currently lasts one session only. Offer to
      write it to the per-target config so it survives, feeding `--exclude`.
- [ ] **Compare screen** — `c` diffs against the previous run from history: new
      registrations, score moves, disappearances. `diff` exists in the CLI and
      the data is already on disk.
- [ ] **Watchlist** — mark a target for a nightly rescan; emit the command for
      cron or a CI job rather than running a daemon.
- [ ] **Settings screen** — theme, density, glyph level, `fail-on` threshold,
      default preset. Written to the existing config location.
- [ ] **Otacon command palette** — a Textual `Provider` so `^p` lists the tool's
      own commands instead of only the framework's.
- [ ] **Export the current view** — whatever the filter shows, to JSON/CSV/HTML.

---

## Phase 5 — console surface

**Goal:** `otacon scan` matches the console's vocabulary and stops being a wall.

- [ ] **Unify badge vocabulary** from `ui/copy.py` across all four surfaces.
- [ ] **Split the overloaded `Domain` column.** It currently carries name,
      badges, technique, the top two reasons and the page title — up to five
      wrapped lines per row, so twelve rows fill a screen and a half.
- [ ] **`--compact` / `--top N`** for a one-line-per-row table.
- [ ] **Fix the `critical` background artefact** (Phase 0 removes the token;
      this is where the call sites are cleaned up).
- [ ] **Gradient degradation** wired through `caps.color_depth()`.
- [ ] **ASCII mode** verified against the `SAFE_GLYPHS` budget on Windows
      terminals.

---

## Phase 6 — HTML report

**Goal:** the artefact that leaves the building looks like it came from a
product.

- [ ] **Typography** — a real UI stack for prose, monospace kept for domains,
      hashes and IPs where it carries meaning.
- [ ] **Light and dark** from the same tokens, following `prefers-color-scheme`,
      and a print stylesheet that survives being turned into a PDF.
- [ ] **Executive summary** — verdict, distribution, the top findings and what
      to do about them, before the table.
- [ ] **Working table** — sort and search, not only the current radio-button
      filters.
- [ ] **Evidence detail per row** — the dossier content, collapsed.
- [ ] **Still one self-contained file, still no external requests.** This is a
      report about phishing; it must not phone home.

---

## Phase 7 — brand and assets

- [ ] **Scalable wordmark** — the current three-line dot logo is the only mark
      and it is tiny. Add a larger lockup for the splash and the start screen,
      keeping the homoglyph `О` as the idea it already is.
- [ ] **Regenerate the README SVGs** per theme once Phases 1–2 land.
      *Blocked on an environment with working DNS.* The README states its
      images are real output, and they currently show the pre-Phase-1
      console and the old brand mark. Regenerating them needs a host that
      can resolve: a cloud container behind an HTTPS-only proxy fails ~78%
      of port-53 lookups, and `tools/render_demo_svg.py` there produces an
      honest "Inconclusive" card rather than a table — which would
      misrepresent the tool as broken. Run both tools from a normal
      workstation:
      ```
      python tools/render_demo_svg.py example.com assets/brand/demo-scan.svg
      python tools/render_tui_svg.py example.com assets/brand/demo-tui.svg
      ```
- [ ] **Theme gallery in the docs** — four themes, two colour depths.

---

## Non-goals

- **No web UI, no daemon, no server.** Otacon stays a CLI tool. The watchlist
  emits a cron line; it does not become a service.
- **No telemetry**, in any surface, under any flag.
- **No external fonts, CDNs or network calls from the HTML report.**
- **No animation that delays input.** Motion is capped at the existing splash
  budget and is skipped under `CI`, `NO_COLOR` and `OTACON_NO_ANIMATION`.
- **No scoring changes.** This document is about presentation; `SCORING.md`
  owns the numbers.

---

## Sequencing

| Phase | Depends on | Size | Why here |
|---|---|---|---|
| ~~0 — tokens~~ | — | M | **Done.** Every other phase is cheaper afterwards |
| ~~1 — hierarchy~~ | 0 | M | **Done.** The loudest defect, visible in one screenshot |
| ~~2 — non-specialist~~ | 0, 1 | M | **Done.** The stated goal of the whole effort |
| ~~3 — scan~~ | 0 | S | **Done.** Closed a real CLI/console regression |
| 5 — console | 0 | S | Mostly deletion once tokens and copy are shared |
| 4 — operator | 1 | L | Largest surface area, lowest urgency |
| 6 — HTML | 0 | M | Independent of everything in the terminal |
| 7 — brand | 1, 2 | S | Screenshots are only worth regenerating once |

Each phase lands as its own pull request with before/after screenshots rendered
by `tools/render_tui_svg.py` and `tools/render_demo_svg.py`, so a reviewer can
see what changed without running a scan.
