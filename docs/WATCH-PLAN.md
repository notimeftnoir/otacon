# Unifying `otacon watch`

Two designs for one command name arrived from opposite directions.

`main` has `otacon watch` as of 3.0.0: it keeps the list of targets worth
re-scanning and prints crontab lines for them. Otacon does not become a daemon
— the machine already has one.

[notimeftnoir/otacon#66](https://github.com/notimeftnoir/otacon/pull/66) has
`otacon watch` as a monitoring run: scan once, compare against the previous
run, report only the differences, optionally POST them to a webhook. Its
measured contribution is alert noise reduction — the PR records 9 and 7 false
escalations per run before hysteresis, 0/2/0 after.

Same name, different jobs, and neither is wrong. This records how they become
one command.

## The finding that shapes the plan

#66 keeps its own SQLite state file with a table of variants, their confirmed
signals, their pending signals and a per-variant miss counter. It needs that
file because, on the branch it was written on, nothing else remembered a
previous scan.

`main` remembers. `history.save` keeps the last `DEFAULT_KEEP = 30` reports per
target as JSON, `history.scans(target, limit)` lists them newest first, and
`triage.verdict.delta(previous, current)` already computes exactly the four
change kinds #66 reports:

| #66 `Event.kind` | `main` `ChangeKind` |
|---|---|
| `new` | `REGISTERED` |
| `escalated` | `ESCALATED` |
| `gone` | `GONE` |
| `discovered` | `FOUND` |

So the SQLite file is not state that has to be ported. It is state that stops
being necessary — and with it goes `State`, `_SCHEMA`, `State.diff`,
`State.save`, `default_state_path` and the `runs`/`variants`/`discoveries`
tables: 237 lines down to roughly 80.

What does **not** come for free is the hysteresis, and that is the part worth
having. It is also derivable rather than stored: "this probe signal was seen in
two runs in a row" and "this variant has been missing two runs in a row" are
questions about the retained reports, so they are computed by replaying
history, not by keeping a counter.

Deriving instead of storing buys three things. No second store to keep in step
with the first. No migration when the shape changes. And it self-heals — delete
a bad report and the derivation corrects itself, where a counter would stay
wrong for good.

The cost is reading up to 30 local JSON files per watched target per run. Set
against a scan that makes a few hundred DNS queries, that is not a cost.

## Model fields #66 expects and `main` does not have

`watch.py` reads three things that came from earlier, unmerged parts of that
stack. Each has an equivalent here or needs none:

| #66 expects | On `main` |
|---|---|
| `report.discovered` (hosts from CT / intel) | not needed — `ct_logs.fetch_ct_domains` folds CT candidates into the permutation list, so they are scanned like any other variant and surface as `ChangeKind.FOUND` |
| `report.inconclusive` (variants DNS could not answer for) | `report.degraded` and `report.dns_failure_ratio` are report-wide, not per variant; the per-variant signal has to be added or the "silence is not removal" rule loosened to a report-wide guard |
| `r.intel_sources` (phishing feed listing) | `r.dnsbl_listed` / `r.dnsbl_source` carry the same meaning for the `reported` signal |

The middle row is the only real gap and it matters: without it, a run whose
resolver half-failed reports working lookalikes as `gone`. The report-wide
guard is the cheaper fix and is strictly safer — when `report.degraded` is
true, emit no `GONE` events at all and say why.

## Command surface

```
otacon watch                      run: scan every watched target, report changes
otacon watch example.com          run for one target, on the list or not
otacon watch --list               show the watchlist
otacon watch --add example.com    put a target on it
otacon watch --remove example.com take one off
otacon watch --cron               print the crontab lines
otacon watch --webhook URL        POST the changes (repeatable)
otacon watch --exit-code          exit 2 when something changed
```

### The one breaking change

Today bare `otacon watch` lists the watchlist. After this it runs a scan.

That is a behaviour change in a command 3.0.0 just shipped, so it costs a major
— and it is the right way round. `watch` is the verb cron calls; a command
whose bare form only prints a list is a command that needs a flag to do its
job. Listing moves to `--list`, which is what it always was.

The alternative keeps the current default and puts the run behind `--run`. It
breaks nothing and reads worse forever. Worth stating plainly rather than
choosing quietly.

## Stages

### Phase A — port what is worth keeping
Status: not started

Into `src/otacon/watch.py` on `main`'s layout, from #66:

- `Event`, `signals`, `_RELIABLE`, `_SIGNAL_WORDS` — the vocabulary of what
  changed, unchanged except `intel_sources` → `dnsbl_listed`.
- `defang` and `summary` — a chat app must not turn a lookalike into a
  clickable link. This is security-relevant, not cosmetic.
- `_payload` and `notify` — per-service body shaping, detected from the webhook
  host.

Dropped: `State`, `_SCHEMA`, `default_state_path`, and the SQLite dependency.

New, replacing `State.diff`: a function over the retained reports that takes
`verdict.delta`'s changes and withholds an `ESCALATED` whose signal has been
seen only once, and a `GONE` whose variant has been missing only once. Suppress
every `GONE` when `report.degraded`.

Tests port from `tests/test_watch.py` (185 lines): baseline, immediate reliable
signals, confirmation over two runs, gone after two misses, flap producing zero
alerts, defang, per-service payload shape, webhook delivery. The flap test is
the one that matters — it is the measurement the hysteresis exists for.

### Phase B — one command
Status: not started

`cli/commands/watch.py` grows the run path beside the list path. The existing
`execute_watch` body becomes the `--list` / `--add` / `--remove` / `--cron`
branch; the new branch loops `config.watched()`, scans each through
`engine.run_scan` honouring that target's `allowed` list, saves to history, and
prints the withheld-filtered changes.

`config.TargetConfig` gains nothing. The watchlist is already there, and the
allow-list already belongs in the same file.

### Phase C — notification and exit code
Status: not started

`--webhook` (repeatable, plus `OTACON_WEBHOOK`, ignoring an empty value from an
unset CI secret) and `--exit-code`. Both are #66's, both port directly.

### Phase D — #67's exports on the unified events
Status: blocked on A–C

[notimeftnoir/otacon#67](https://github.com/notimeftnoir/otacon/pull/67) adds
`watch --syslog` on top of #66's events. Once the events come from here it
ports as a renderer over `list[Event]`, with no state of its own.

## Out of scope

[notimeftnoir/otacon#65](https://github.com/notimeftnoir/otacon/pull/65)
(ASN, RDAP, evidence pack) and
[notimeftnoir/otacon#68](https://github.com/notimeftnoir/otacon/pull/68)
(`otacon check`) collide with nothing here. They are separate ports and share
only the same obstacle: that whole stack is based on `7262464`, which predates
the v2.0.0 modularisation, so all four branches still carry
`src/otacon/cli.py` as one file against a tree that has a `cli/` package. None
of them is a rebase. Each is a port.
