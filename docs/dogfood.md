# Dogfood log: an agent driving real apps with testkit

Sessions where Claude drove an app only through testkit (CLI session daemon and `testkit mcp`), deciding each step from the previous reply. Each finding was fixed and covered by the self-test suite unless noted.

## 2026-10-29 · TodoMVC (https://demo.playwright.dev/todomvc/) via CLI and MCP

Flow: visit → add two todos (fill + Enter) → complete one → filter "Completed" → edit by double-click → claim → receipt. The recorded file replayed green (9/9 steps, 1.5s), and the MCP claim produced a proven receipt.

| # | What went wrong | Fix |
|---|---|---|
| 1 | Adding a todo didn't show up in the step report: list items and rows weren't part of the change summary | `listitem` and `row` are summarised, so `appeared listitem "buy milk"` |
| 2 | The counter "2 items left" showed as `text: "2"`: loose text nodes beside elements were dropped from snapshots | Snapshots include mixed text nodes and merge neighbours (`text: "1 item left"`) |
| 3 | `snapshot main` printed an empty snapshot on a page without `<main>` | `E_NOT_FOUND` naming the landmarks that do exist (`list, contentinfo`) |
| 4 | MCP replies repeated the full element description as `it = {…}`, hundreds of tokens per step | `it` prints as `checkbox "Toggle Todo" [checked]`; element lists show a count plus the first three |
| 5 | After `check`, `it` still showed `checked: false` (the state before the action) | Actions return the element as it is after the action |
| 6 | Receipt header showed "git ``" and an empty base URL outside a repo | Empty fields are omitted |
| 7 | Toggling a checkbox showed only `appeared button "Delete"`: state changes were invisible in diffs | Summaries carry `[checked]` / `[expanded]`; `suggest` proposes `is checked`, `is expanded` and `no X` for removals |

What worked without changes: ref → stable-locator rewriting on record (`@e3` → `textbox "What needs to be done?"`), scoped locators (`checkbox "Toggle Todo" in listitem "buy milk"`), hash-route navigation detection (`url /todomvc/#/ → /todomvc/#/completed` plus a fresh snapshot), budget-sized replies (all under 700 characters), and an empty console observed through `observe`.

Open observations:
- The `step` tool description (the grammar cheat sheet) is about 3.5k characters. That's fine for one tool, but worth trimming if clients load many MCP servers.
- Generic `text: "Mark all as complete"` lines duplicate a checkbox's label; Playwright snapshots have the same redundancy.
