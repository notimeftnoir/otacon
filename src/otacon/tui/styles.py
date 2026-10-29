"""Textual CSS for the Otacon triage console.

Held as a string rather than a .tcss file so the stylesheet ships with the
wheel without any package-data plumbing.

Every colour arrives as an ``$otacon-*`` design token from
:func:`otacon.ui.emit.textual_vars`, fed in through
``OtaconTUI.get_css_variables``. This file used to repeat the palette as hex
literals and needed a test to catch the two copies drifting apart; with the
literals gone there is nothing left to drift, and the console gains every
theme for free.

Design intent: a dense instrument panel, not a document. Square borders, no
rounded corners, no gradients behind text, one accent used sparingly, and risk
expressed by hue *and* by glyph density so the left rail reads correctly even
with no colour at all.
"""

from __future__ import annotations

OTACON_CSS = """
Screen {
    background: $otacon-bg;
    color: $otacon-body;
    layers: base overlay;
}

/* ── top strip: identity and tally ─────────────────────────────────────── */

#masthead {
    height: 3;
    background: $otacon-surface;
    border-bottom: solid $otacon-line;
    padding: 0 1;
}

#brand {
    width: auto;
    content-align: left middle;
    height: 100%;
}

#tally {
    width: 1fr;
    content-align: right middle;
    height: 100%;
}

/* ── body: dossier on the left, table rail on the right ────────────────── */

#body {
    height: 1fr;
}

#rail {
    width: 2fr;
    border-left: solid $otacon-line;
}

/* The rail takes two thirds: its columns are fixed-width, and FLAGS — the
   column that changes what an operator does with a row — is the one that gets
   clipped first when the table is squeezed. The dossier reflows instead. */
#dossier {
    width: 1fr;
    padding: 1 2;
    overflow-y: auto;
}

#dossier-empty {
    color: $otacon-dim;
    text-align: center;
    padding: 4 0;
}

DataTable {
    height: 1fr;
    background: $otacon-bg;
    scrollbar-size-vertical: 1;
}

DataTable > .datatable--header {
    background: $otacon-surface;
    color: $otacon-muted;
    text-style: bold;
}

DataTable > .datatable--cursor {
    background: $otacon-select;
    color: $otacon-strong;
    text-style: bold;
}

DataTable > .datatable--hover {
    background: $otacon-raised;
}

/* ── status bar: what the transient toasts used to say, but permanently ── */

/* Height 2, not 1: border-top occupies a row of the box, so a one-row
   widget with a border has nowhere left to draw its text. */
#statusbar {
    height: 2;
    background: $otacon-surface;
    color: $otacon-muted;
    border-top: solid $otacon-line;
    padding: 0 1;
}

/* ── filter bar ────────────────────────────────────────────────────────── */

#filterbar {
    height: 2;
    background: $otacon-surface;
    border-top: solid $otacon-line;
    padding: 0 1;
    display: none;
}

#filterbar.visible {
    display: block;
}

Input {
    background: $otacon-surface;
    color: $otacon-strong;
    border: none;
    height: 1;
    padding: 0;
}

Input:focus {
    border: none;
}

/* ── dossier internals ─────────────────────────────────────────────────── */

.verdict {
    height: auto;
    padding: 0 0 1 0;
    border-bottom: solid $otacon-line;
    margin-bottom: 1;
}

.section-label {
    color: $otacon-brand-dim;
    text-style: bold;
    margin-top: 1;
}

#notice {
    layer: overlay;
    width: 80%;
    height: 80%;
    offset: 10% 10%;
    background: $otacon-surface;
    border: solid $otacon-brand;
    padding: 1 2;
    overflow-y: auto;
    display: none;
}

#notice.visible {
    display: block;
}

/* ── help overlay ──────────────────────────────────────────────────────── */

#help {
    layer: overlay;
    width: 86%;
    height: 86%;
    offset: 7% 7%;
    background: $otacon-surface;
    border: solid $otacon-accent;
    padding: 1 2;
    overflow-y: auto;
    display: none;
}

#help.visible {
    display: block;
}

/* ── overview: the screen a finished scan lands on ─────────────────────── */

#overview {
    width: 1fr;
    height: 1fr;
    padding: 1 4;
}

/* Capped rather than centred: the rest of the console is a left-aligned
   instrument panel, and a centred column on a wide terminal reads as a
   different application. */
#overview-body {
    height: auto;
    max-width: 96;
}

/* ── compare: what moved since last time ───────────────────────────────── */

#compare {
    width: 1fr;
    height: 1fr;
    padding: 1 4;
}

#compare-body {
    height: auto;
    max-width: 96;
}

/* ── settings, allow-list and watchlist ────────────────────────────────── */

#settings {
    width: 1fr;
    height: 1fr;
    padding: 1 4;
}

#settings-note {
    padding-bottom: 1;
}

#settings OptionList {
    background: $otacon-bg;
    border: none;
    height: auto;
    padding: 0;
}

#settings OptionList:focus {
    border: none;
}

#settings OptionList > .option-list--option-highlighted {
    background: $otacon-select;
    color: $otacon-strong;
    text-style: bold;
}

/* ── start screen ──────────────────────────────────────────────────────── */

#preset-label {
    color: $otacon-brand-dim;
    text-style: bold;
    padding-top: 1;
}

#setup RadioSet {
    background: $otacon-surface;
    border: none;
    height: auto;
    padding: 0;
    margin-bottom: 1;
}

#setup RadioSet:focus {
    border: none;
}

#setup RadioButton {
    background: $otacon-surface;
    padding: 0;
}

#setup Collapsible {
    background: $otacon-surface;
    border: none;
    padding: 0;
}

#setup CollapsibleTitle {
    color: $otacon-muted;
    padding: 0;
}

#setup CollapsibleTitle:hover {
    color: $otacon-brand;
    background: $otacon-surface;
}

#setup {
    width: 68;
    height: auto;
    padding: 2 3;
    background: $otacon-surface;
    border: solid $otacon-line;
}

#setup-brand {
    text-style: bold;
    padding-bottom: 1;
}

#setup-help {
    color: $otacon-muted;
    padding-bottom: 1;
}

#setup #target {
    border: solid $otacon-line;
    height: 3;
    padding: 0 1;
    margin-bottom: 1;
}

#setup #target:focus {
    border: solid $otacon-brand;
}

#setup Checkbox {
    background: $otacon-surface;
    border: none;
    height: 1;
    padding: 0;
}

#setup Checkbox:focus {
    text-style: bold;
}

#setup-status {
    height: auto;
    padding-top: 1;
}

#setup-progress {
    padding-top: 1;
}

#recent-label {
    color: $otacon-brand-dim;
    text-style: bold;
    padding-top: 1;
}

#recent {
    height: auto;
    max-height: 9;
    background: $otacon-surface;
    border: none;
    padding: 0;
}

#recent > .option-list--option-highlighted {
    background: $otacon-select;
    color: $otacon-strong;
    text-style: bold;
}

Footer {
    background: $otacon-surface;
    color: $otacon-muted;
}

Footer > .footer--key {
    background: $otacon-select;
    color: $otacon-brand;
    text-style: bold;
}

Toast {
    background: $otacon-surface;
    border: solid $otacon-brand;
}
"""

__all__ = ["OTACON_CSS"]
