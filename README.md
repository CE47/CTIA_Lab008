# CTI Casefile 008 — The Empty Folder

A single-page, browser-based **cyber threat intelligence investigation simulator**,
built from the scenario spec in `new.scenario`.

You are a Tier 1 escalation analyst. Three alerts fired on one workstation and nobody
has told you which of them matter. You get the raw event stream, three alerts, an
account record and a host baseline for the estate. You have to work out what actually
happened, prove it, name it, and write an assessment someone else can act on.

One case, six stages, 100 XP, about 25 minutes.

**No account. No setup. No terminal. No Wireshark, no VM, no SIEM licence.**

---

## Play it

The case runs entirely in the browser — no build step, no installation, no account.
Progress is saved locally to the browser only.

Open `index.html` in any current browser and press **BEGIN INVESTIGATION**. It also
runs from a local disk over `file://`, and deploys unchanged as a static page (GitHub
Pages, Netlify, or any web server).

---

## The case

`rneuman` logged on to `sec-win-03` at 08:03:16 and opened the share
`Finance\Quarterly Close` on the file server at 10.0.4.12. The file server's own object
audit then recorded **50 delete operations in five minutes** — more than ten times that
account's 30-day average for the same folder — and the session closed by user action 43
seconds after the last one. The folder fell from 214 files to 164. No restore was
requested for four hours.

Everything you are given — three alerts, the event stream, the account and usage record,
the estate baseline — is in `new.scenario`. Nothing in this folder names a technique, an
indicator or a responsible host until you have earned it from the evidence.

**Where the evidence lives matters here.** The deletion appears in no Windows event log
at all — it is in the file server's object audit, which is why the case is solvable at
all and why an endpoint-only investigation would close having learned nothing. That is
also why one record in the stream is a `FILE` audit record rather than a Windows event id.

---

## How the case works

| Stage | Name | What you do | XP |
|---|---|---|---|
| — | Briefing | Read the mission, press BEGIN | — |
| 01 | **Detect** | Open all five evidence items | 10 |
| 02 | **Collect** | Tag 24 log lines SIGNAL / CONTEXT / NOISE | 10 |
| 03 | **Correlate** | Order the timeline, name the pattern | 10 |
| 04 | **Connect** | Draw the threads on the pinboard | 10 |
| 05 | **Analyze** | Behaviour, deletion record, ATT&CK, classify IoCs | 42 |
| 06 | **Report** | Scope, findings, justification, confidence, response | 18 |

Then a debrief sheet: rank, XP ledger, preserved indicators, and your analyst journal.

**Analyst Assist** offers three levels of help and never blocks you. A wrong answer
lowers your score and rank; it never blocks progress, and any section can be
re-answered with **TRY AGAIN**. `RESET CASEFILE` clears saved progress.

---

## Answer order

The order of every question's options is decided at load time from the case seed
(`seed: 111`), not by whoever typed the question — see `shuffleCase()` in `app.js`.

- **Deterministic.** The same case always produces the same order, so reloading
  mid-question never moves an answer under your cursor, and refreshing does not
  reshuffle anything to your advantage.
- **Independent per question.** A different permutation for each question, so no
  slot is worth guessing and clicking the top option ten times scores almost
  nothing. The indicator chips are shuffled for the same reason: the two actionable
  ones are not always the first two.

Grading is by option id throughout, so the shuffle cannot change what is correct —
only where the correct answer sits on screen.

---

## Files

| File | Purpose |
|---|---|
| `index.html` | the whole page: briefing, generic stage host, evidence modal, debrief sheet |
| `style.css` | the paper-and-stamp design system, print styles, reduced-motion support |
| `app.js` | the engine — six stages, scoring, XP ledger, save/resume, accessibility, option shuffling |
| `board.js` | the correlation board — draggable cards, drawn threads, keyboard support |
| `scenarios/beginner-mass-deletion-001.js` | the case: evidence, log stream, timeline, board, questions, IoCs, ranking |
| `new.scenario` | the JSON brief this case was built from — the source of truth for content |

The engine contains no facts about this case. Headings, ledger lines, the trail card
and the report preview all come from the scenario file's `engine` block, so a
different scenario is a different data file, not a different engine.

---

## Accessibility notes

- The whole game is playable with the keyboard alone. Tab to a board card and press
  Enter or Space to arm it, Tab to the second card and press Enter to choose a
  relation, then Enter on the verb. Escape cancels a pending thread.
- Focus is trapped inside the evidence modal and the debrief sheet, and returns to
  the element that opened them.
- `prefers-reduced-motion` is respected.
- There is a `@media print` block — the debrief sheet prints as a clean intelligence
  product.

## Browser support

Any current evergreen browser. Uses `localStorage`, Pointer Events, CSS custom
properties and `Element.closest`. Degrades to "plays without saving" if
`localStorage` is unavailable (private mode).