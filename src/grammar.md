# testkit grammar (cheat sheet)

A step is `verb: expression`. In YAML each item is one step; on the CLI `testkit <verb> '<expression>'`.
Structured data (objects, lists, aria trees) goes in sibling keys, never inside the expression.

## Locators (what you point at)
- `button "Sign in"`, `link "Docs"`, `heading "Orders"`, `row /Alice/`, `checkbox "Remember me"`: ARIA role + name (case-insensitive substring; `exactly "…"` or `/regex/i`)
- `field "Email"` (label/placeholder), `text "Welcome"`, `testid "checkout"`, `<css selector/>`, `@e12` (ref from `snapshot`)
- Scope and position: `button "Edit" in row /Alice/`, `first link in navigation`, `closest form to field "Email"`, `row has button "Edit"`, `<li/>[2]`
- Terminal: `text /listening on :(\d+)/ in server`, `line 3`, `last line`
- Actions are strict: when a locator matches several elements, the error lists a unique locator for each one.

## Verbs
- Browser: `visit: /login` · `click:` · `dblclick:` · `hover:` · `check:` · `uncheck:` · `fill: field "Email" with "a@b.co"` · `select: field "Plan" with "Pro"` · `upload: field "Avatar" with "me.png"` · `type: "abc"` · `press: Enter` / `ctrl+a` / `down 3 times` · `drag: text "Card" to region "Done"` · `back:` · `reload:`
- API: `GET: /api/orders` (with `headers:`, `json:`, `params:`, `cookies: from default`)
- Terminal: `exec: cargo --version` (one-shot) · `spawn: npm run dev` (+ `session:`, `ready: for text /ready/ or 60s`, `size: 120x40`, `prompt: /\$ $/`) · `enter: "help"` · `signal: SIGTERM to server` · `resize: 80x24`
- Flow: `wait: for request "POST /api/orders" or 5s` · `wait: <cond>` · `extract: its json's id into order_id` · `call: flows/login.tk.yaml` (+ `with:`, `exports:`) · `route: POST /api/orders` (+ `respond:`/`modify:`/`abort:`/`delay:`)
- Intent: `act: sign in as the admin` → Claude resolves it to concrete steps from the snapshot, runs them (retrying with the error), caches them in `.testkit/act/` and records the concrete steps (`TESTKIT_ACT_CMD` swaps in another resolver)
- Proof: `claim: Users can create orders` · `shot: home.png` · `snapshot: main` · `measure: true` on an action
- Devtools: `trace: start` / `trace: stop into checkout` · `profile:` · `throttle: cpu 4x` · `network: slow 3g` · `emulate: iPhone 15 | dark | reduced-motion`

## Assertions (`expect:` retries until it passes or times out; `asserts: [ok: …]` on a step)
- `heading "Dashboard" is visible` · `button "Pay" is disabled` · `no row /Alice/` · `no console errors`
- `the status of request "POST /api/orders" is 201` · `its json's id is 1043` · `the json contains "Alice"`
- `the url of page contains "/dashboard"` · `the lcp of page is less than 2.5s` · `its duration is less than 300ms`
- `the length of (orders where its status is "paid") is 2` · `name matches /^A/ ignoring case` · `x is between 1 and 5` · `x is a Number`
- Structural: `expect: table "Orders"` + `matches:` with a partial aria snapshot; `expect: screen` + `matches:` with lines; `expect: json` + `matches: {…}`; `matches: golden/file.txt`
- Mixing `and`/`or` needs parentheses. `it` = the previous step's result. `${var}` / `${env.X}` interpolate.

## Words with two meanings (decided by position)
- `status` alone is the HTTP status of the last API step; `status "Ready"` is the ARIA `status` role.
- `text "Welcome"` is a locator; `the text of <h1/>` / `its text` is a property.
- `matches` is a regex match when the right side is a string or `/regex/`, and a structural match when it is a locator.
- `testkit lint` flags YAML traps (`: ` or ` #` inside a value), fixed sleeps, volatile literals, legacy `{{x}}` and brittle CSS.

## Example
```yaml
- visit: /login
- fill: field "Email" with "${user}"
- fill: field "Password" with "${env.PASS}"
- click: button "Sign in"
- expect: heading "Dashboard" is visible
- claim: A user can create an order
- click: button "New order"
- fill: field "Customer" with "Alice"
- click: button "Save"
- expect: the status of request "POST /api/orders" is 201
- expect: alert "Order created" is visible
```
Loop: `snapshot` → act → read the step report (what appeared, network, console) → `expect` → `claim end` → paste receipt.md.
