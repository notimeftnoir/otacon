"""Textual CSS for the Otacon TUI.

Held as a string rather than a .tcss file so the stylesheet ships with the
wheel without any package-data plumbing.

Design intent: a dense instrument panel, not a document. Square borders, no
rounded corners, no gradients behind text, one accent colour used sparingly, and
risk expressed by hue so a glance at the left rail reads the whole picture. The
palette is the same semantic set as OTACON_THEME in utils/theme.py — kept in
these literals because Textual CSS cannot read Python constants, and asserted
equal by tests/test_tui.py so the two cannot drift.
"""

from __future__ import annotations

OTACON_CSS = """
Screen {
    background: #0a0e0f;
    color: #d0d0d0;
    layers: base overlay;
}

/* ── top strip: identity and tally ─────────────────────────────────────── */

#masthead {
    height: 3;
    background: #0d1214;
    border-bottom: solid #1c2628;
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
    border-left: solid #1c2628;
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
    color: #5a5a5a;
    text-align: center;
    padding: 4 0;
}

DataTable {
    height: 1fr;
    background: #0a0e0f;
    scrollbar-size-vertical: 1;
}

DataTable > .datatable--header {
    background: #0d1214;
    color: #8a8a8a;
    text-style: bold;
}

DataTable > .datatable--cursor {
    background: #16302b;
    color: #ffffff;
    text-style: bold;
}

DataTable > .datatable--hover {
    background: #121a1b;
}

/* ── filter bar ────────────────────────────────────────────────────────── */

#filterbar {
    height: 1;
    background: #0d1214;
    border-top: solid #1c2628;
    padding: 0 1;
    display: none;
}

#filterbar.visible {
    display: block;
}

Input {
    background: #0d1214;
    color: #ffffff;
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
    border-bottom: solid #1c2628;
    margin-bottom: 1;
}

.section-label {
    color: #00875f;
    text-style: bold;
    margin-top: 1;
}

#notice {
    layer: overlay;
    width: 80%;
    height: 80%;
    offset: 10% 10%;
    background: #0d1214;
    border: solid #00d7af;
    padding: 1 2;
    overflow-y: auto;
    display: none;
}

#notice.visible {
    display: block;
}

Footer {
    background: #0d1214;
    color: #8a8a8a;
}

Footer > .footer--key {
    background: #16302b;
    color: #00d7af;
    text-style: bold;
}

Toast {
    background: #0d1214;
    border: solid #00d7af;
}
"""

__all__ = ["OTACON_CSS"]
