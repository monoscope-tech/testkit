<div align="center">

# Testkit

[![APItoolkit OSS](https://img.shields.io/badge/APItoolkit-OSS-0068ff?logo=rust)](https://github.com/topics/apitoolkit) [![](https://img.shields.io/github/v/release/apitoolkit/testkit)](https://github.com/apitoolkit/testkit/releases) [![](https://img.shields.io/github/downloads/apitoolkit/testkit/total)](https://github.com/apitoolkit/testkit/archive/refs/heads/main.zip) [![Join Discord Server](https://img.shields.io/badge/Chat-Discord-7289da)](https://apitoolkit.io/discord?utm_campaign=devrel&utm_medium=github&utm_source=testkit_readme)

Testkit is a small language and CLI for **operating, testing and proving** apps (HTTP APIs, browsers and terminals), built by the [APItoolkit](https://apitoolkit.io?utm_campaign=devrel&utm_medium=github&utm_source=testkit_readme) team and amazing community [contributors](https://github.com/apitoolkit/testkit/graphs/contributors). The same one-line steps run from YAML files, the command line, a REPL and an MCP server, so people and LLM agents can drive an app, read it semantically and hand back a verifiable proof that a feature works.

![Testkit demo](https://github.com/apitoolkit/testkit/assets/6564482/d1f7ec76-b81b-4036-a87b-b8bda562d03c)

</div>

---

## Table of Contents

- [At a glance](#at-a-glance)
- [Installation](#installation)
- [Steps and expressions](#steps-and-expressions)
- [Driving an app from the CLI (and agents)](#driving-an-app-from-the-cli-and-agents)
- [Proofs and receipts](#proofs-and-receipts)
- [Performance and DevTools](#performance-and-devtools)
- [CI](#ci)
- [Testkit tests itself](#testkit-tests-itself)
- [Legacy API syntax](#legacy-api-syntax)

## At a glance

```yaml
- meta: { base_url: "http://localhost:${port}" }
- spawn: npm run dev                       # terminal surface: start the app
  session: server
  ready: for text /localhost:(\d+)/ or 60s
- extract: its match[1] into port
- visit: /login                            # browser surface
- fill: Email with "admin@acme.com"      # bare names: the field / button with that name
- fill: Password with "${env.PASS}"
- click: Sign in
  expect: the url ends with "/dashboard"   # `expect:` works as a key on any step
- expect: no console errors
- claim: A user can create an order        # a named proof
- click: New order
- fill: Customer with "Alice"
- click: Save
- expect: the status of request "POST /api/orders" is 201
- GET: /api/orders                         # API surface, same session cookies
  cookies: from default
  expect: [status is 200, json contains "Alice"]
```

```console
$ testkit test                 # every *.tk.yaml under the current directory
$ testkit prove orders.tk.yaml # run it and write a receipt (GIFs, hashes, receipt.md)
$ testkit click 'button "Save"'   # one step against a live CLI session
$ testkit mcp                  # the same grammar as an MCP server for agents
```

## Installation

To install `testkit`, kindly follow one of the options below (click on the toggle):

<details>
<summary><b>Download Binaries</b></summary>
<br />
   
Navigate to the [releases page](https://github.com/apitoolkit/testkit/releases), download the latest version of the `testkit` binary suitable for your operating system (Windows, macOS, or Linux), and proceed to install.

| Binary File    | Description         |
|----------------|---------------------|
| `testkit-release-test-i686-pc-windows-msvc.zip`       | 32-bit Windows (MSVC)   |
| `testkit-release-test-x86_64-pc-windows-msvc.zip`     | 64-bit Windows (MSVC)   |
| `testkit-release-test-x86_64-pc-windows-gnu.zip`      | 64-bit Windows (GNU)    |
| `testkit-release-test-x86_64-apple-darwin.tar.gz`     | 64-bit macOS (Darwin) |
| `testkit-release-test-x86_64-unknown-linux-gnu.tar.gz`| 64-bit Linux (GNU)    |


After downloading, extract the zip file and proceed to install the extracted file. Alternatively, if you're using macOS, you can use Homebrew to install, like so:

1. Tap the `testkit` release repository to add it as a source for Homebrew formulae using the command below:

   ```bash
   brew tap apitoolkit/testkit
   ```

2. Install `testkit` using the command below:

   ```bash
   brew install testkit
   ```

</details>

<details>
<summary><b>Clone Repository</b></summary>
<br />

Kindly follow the steps below to build the project locally:

1. Ensure you have [Rust](https://rust-lang.org) programming language and [Cargo package manager ](https://doc.rust-lang.org/cargo/getting-started/installation.html)installed on your computer.

2. Clone the `testkit` repository from GitHub using the command below:

   ```bash
   git clone https://github.com/testkit/testkit
   ```

3. Open the cloned directory using the command below:

   ```bash
   cd testkit
   ```

4. Build the project using the Cargo command below:

   ```bash
   cargo build --release
   ```

5. Once the build process is complete, you will find the `testkit` executable file in the `target/release` directory.

6. Run the `testkit` CLI tool, using the command below:

   ```bash
   testkit test --file ./test.tk.yaml
   ```

7. For further testing, ensure to replace the `./test.tk.yaml` with the path to your YAML test file.

</details>

<br />

> [!NOTE]
>
> Once `testkit` is installed succesfully, run the `testkit --help` command for all CLI commands and options.

## Steps and expressions

A test file is a YAML list. Every item is one `verb: expression`; structured data (objects, lists, aria trees)
goes in sibling keys such as `json:`, `with:`, `respond:` or `matches:`. `testkit grammar` prints the full cheat sheet
([src/grammar.md](src/grammar.md)); the design spec lives in the repository history.

- **Locators** follow the accessibility tree, like Playwright: `button "Sign in"`, `field "Email"`, `text "Welcome"`,
  `testid "checkout"`, `<css/>`, scoped with `button "Edit" in row /Alice/`. Actions also take a bare name:
  `click: Sign in` (the interactive element with that name), `fill: Email with "a@b.co"` (that field).
  In conditions a quoted string is visible text: `expect: '"Order created"'`, `no "Invalid password"`. Actions auto-wait for elements to be visible,
  stable and enabled, and are strict: an ambiguous locator fails with a unique locator for every candidate.
- **Expressions** are hyperscript-flavoured: `json.id is 1043`, `the title is "Acme"` (bare properties read the
  previous step's result, or the page for `title`/`url`/`path`), `the status of request "POST /api/orders" is 201`,
  `no row /Alice/`, `the length of (orders where its status is "paid") is 2`, `name matches /^A/ ignoring case`.
  `it` is the previous step's result; `${var}` and `${env.X}` interpolate.
- **Verbs** cover the browser (`visit click fill check upload type press drag back reload`), HTTP (`GET POST PUT …`),
  terminals (`exec spawn enter signal resize`), flow (`wait extract call route claim`) and evidence (`snapshot shot trace profile`).
- `expect:` retries until it passes, as a step or as a key on any step (`expect: [status is 201, json.id is a Number]`). Console and network subjects look at what happened since the last action,
  and a run-wide guard fails a step that triggers a console error or an uncaught exception (`allow: [console errors]` to opt out).
- Structural checks: `expect: table "Orders"` + `matches:` with a partial aria snapshot, `expect: screen` + lines,
  `expect: json` + a partial JSON shape, or `matches: golden/file.txt` (`--update-golden` refreshes).
- `route:` mocks responses for the browser and for API steps; `call: flows/login.yaml` composes files (`with:` in, `exports:` out).

## Driving an app from the CLI (and agents)

The first CLI step starts a background session daemon (`--session name` for more than one). Each command prints a
semantic step report: what appeared or disappeared, URL changes, network calls and console errors.

```console
$ testkit visit http://localhost:3000/login      # prints an aria snapshot with [ref=eN] refs
$ testkit fill @e3 --value admin@acme.com --record login.tk.yaml
$ testkit click 'button "Sign in"' --record login.tk.yaml
✓ click button "Sign in"  85ms
  url      /login → /dashboard
  appeared heading "Dashboard" · alert "Welcome back" · navigation "Main"
  network  POST /api/session 200 · GET /api/me 200 1ms
$ testkit expect 'heading "Dashboard" is visible' --record login.tk.yaml
$ testkit find Orders · testkit explain '<expr>' · testkit observe network · testkit suggest
$ testkit repl                                   # one step per line
$ testkit session attach http://localhost:9222   # drive your own running Chrome
```

Recording writes stable locators (refs become `textbox "Email"`), turns typed passwords into `${env.PASSWORD}`, and
reuses variables for values it has seen. `testkit mcp` exposes `step`, `snapshot`, `find`, `observe`, `claim` and
`receipt` tools; `testkit init --agents` adds the grammar to `AGENTS.md`/`CLAUDE.md` and a skill file.

## Proofs and receipts

`claim:` items split a file into named claims (steps before the first claim are setup). `testkit prove file.tk.yaml`
runs it without retries and writes `.testkit/receipts/<id>/`:

- `receipt.md`: a status table per claim with an animated GIF, ready for a PR or an agent reply
- `receipt.html`: a self-contained viewer with every step's screen, report and error
- `receipt.json`: the manifest, including git SHA, environment, redactions and the sha256 of every artifact chained into one hash

Secrets that came from `${env.*}`, cookies and auth headers are redacted before hashing. `testkit receipt <id> --verify`
detects any edited artifact. In a CLI session or over MCP: `claim "…"`, steps, then `claim end`.

## Performance and DevTools

`the lcp of page`, `cls`, `inp`, `fcp`, `ttfb`, `the heap of page`, `the nodes of page`, `long tasks`, `a11y violations`
are assertable. `measure: true` on an action records `duration`, `visual`, `network` and `dom` milestones.
`trace: start` / `trace: stop into name` and `profile:` write files DevTools opens; `throttle: cpu 4x`,
`network: slow 3g` and `emulate: iPhone 15 | dark | reduced-motion` change conditions. Baselines:
`expect: the lcp of page is within 10% of baseline "home"` after `testkit baseline update file.tk.yaml`; values near a
threshold are re-sampled and decided on the median.

## CI

`testkit test -o junit|tap|json|github` (GitHub annotations point at the failing YAML line), `-j 4`, `--shard 2/4`,
`--retries 1` (a pass after a retry is reported as `flaky`; `--fail-on-flaky` to fail), `--repeat 20` to hunt flakes.
With `CI=true` the browser clock, timezone, randomness and animations are pinned. Exit codes: 0 pass, 1 failure,
2 invalid file or infrastructure error. `testkit install chrome` fetches Chrome for Testing when Chrome is missing.

## Testkit tests itself

`tests/tk/*.tk.yaml` drive a fixture app (`tests/app`) and the `testkit` binary itself through `exec:`/`spawn:`: the CLI,
error messages, reporters, sessions and recording, the REPL, proofs and tamper detection, the MCP server, perf and
operations. `cargo test` runs them (`TK_FILTER=05 cargo test --test selftest` for one file); a failing claim there is a
gap in testkit. They need Python 3 and Chrome (set `CHROME` to its path if it isn't `google-chrome`/`chromium` or the macOS default).

## Legacy API syntax

Files written for earlier versions keep working: `{{var}}`, `$.env.X`, `$.resp.*` JSONPath and typed asserts
(`array:`, `numberAll:`, `contains: path ~ value` …). `testkit migrate file.yaml` rewrites `{{x}}` / `$.env.X` to `${…}`, `select:` to `fill:`, and `asserts:` lists of only `ok:` to `expect:`.
The original reference follows.

### Test Definition Syntax

Testkit uses a YAML-based syntax for defining test scenarios. Each scenario consists of multiple stages, where each stage represents a specific API request and its associated assertions. Below is an example of the YAML syntax for defining API tests:

```yaml
---
    - title: fetches TODO items - GET
      GET: /todos/
      asserts:
        - ok: $.resp.status == 200
        - array: $.resp.json
      exports:
        todoItem: $.resp.json[0]._id

    - title: deletes TODO items - DELETE
      DELETE: /todos/$.stages[0].todoItem
      asserts:
        - empty: $.resp.json.todos
        - string: $.resp.json

    - title: Adds Todo item - POST
      POST: /todos/
      json:
          task: "run tests"
      asserts:
        - ok: $.resp.status == 200
        - ok: $.resp.json.task == "run tests"
        - ok: $.resp.json.completed
```

In the example above, the YAML test file defines three test items fetching TODO items using a GET request, deleting a specific TODO item using a DELETE request, and adding a new TODO item using a POST request. The YAML file consists of a list of test scenarios. Each scenario represents an API request and contains the following fields:

| Field         | Description    |
|---------------|----------------|
| `title` (required)      | A descriptive name for the stage.      |
| `request` (required)    | Defines the API request to be made, including HTTP methods and the URL.      |
| `asserts` (optional)    | Optional. Defines assertions to be performed on the response for validation.  |
| `exports` (optional)    | Optional. Specifies values to capture from the response for future stages.  |

Kindly click each toggle below to learn more about each field.

<details>
<summary><b><code>request</code> field</b></summary>
<br />

The `request` field in `testkit` defines the API request to be made and consists of three properties:

1. `method` (required): This property specifies the HTTP method for the request, such as `GET`, `POST`, `PUT`, or `DELETE`. The value of the `method` property is the request URL path. Example:

  ```yaml
  # POST request
  - title: Adds Todo item - POST
    POST: /todos/

  # GET request
  - title: Fetches Todo items - GET
    GET: /todos/
  ```

2. `headers` (optional): This property allows you to include HTTP headers in the request. Headers can be used to pass additional information to the server, such as authentication tokens or content types. Example:

  ```yaml
  - title: Fetches Todo items - GET with headers
    GET: /todos/
    headers:
      Authorization: Bearer <token>
      Content-Type: application/json
      Allowed-Methods:
        - GET
        - POST
  ```

3. `json` (optional): This property allows you to include request body data in JSON format when necessary. By specifying the `json` property within the `request` field, you can provide structured data that needs to be sent along with the API request. Example:

  ```yaml
  - title: Create User - POST
    POST: /users/
    json:
      name: John Doe
      age: 25
      email: john.doe@example.com
  ```

In the above example, a POST request is made to create a new user. The `json` property contains the user data in JSON format, including properties such as `name`, `age`, and `email`. Including the `json` property in the `request` field enables you to pass structured data to the API endpoint, facilitating actions such as creating or updating resources on the server.

These properties in the `request` field provide flexibility and control over the API requests made during testing. You can specify the HTTP method and include headers as needed to interact with the API endpoints effectively.

</details>

<details>
<summary><b><code>asserts</code> field</b></summary>
<br />

The `asserts` field in `testkit` plays a crucial role in defining assertions or validations to be performed on the API response. It allows you to specify conditions that must be met for the test to pass successfully. The field accepts a collection of key-value pairs, where the keys represent the type of assertion (think of it as a variable) and the values define the corresponding expressions or conditions to be evaluated. You can include multiple assertions within the `asserts` field to perform various validations on different aspects of the API response, such as checking specific properties, verifying the presence of certain data, or comparing values.

Here's an example to demonstrate the usage of the `asserts` field:

```yaml
- title: Fetches Todo items - GET
  GET: /todos/
  asserts:
    - ok: $.resp.status == 200
    - array: $.resp.json
    - ok: $.resp.json[0].task == "run tests"
```
<br />

> NB: The `.json` in `$.resp.json` tells `testkit` to convert the response into JSON format. This allows you to access properties of the response JSON using JSONPath expressions.

In the above example, we have defined three assertions:

1. `ok`: This assertion checks whether the response status code is equal to 200. The expression `$.resp.status == 200` is evaluated, and if it returns `true`, the assertion is considered successful.

2. `array`: This assertion verifies that the response body is an array. The expression `$.resp.json` is evaluated, and if the result is an array, the assertion is considered successful.

3. `ok`: This assertion checks if the first Todo item retrieved from the API response has a task name equal to "run tests". The expression `$.resp.json` is evaluated, and if it returns `true`, the assertion is considered successful.

By utilizing the `asserts` field effectively, you can ensure that the API response meets the expected criteria, providing confidence in the correctness and reliability of your API. All possible assertions you could use are as follows:

| Assertion | Description     |
|-----------|-----------------|
| `ok`     | Checks if the provided expression evaluates to `true`. |
| `empty`  | Checks if a value is empty (e.g., an empty array, string, or null). |
| `array`  | Checks if a value is an array.                  |
| `string` | Checks if a value is a string.                  |
| `number` | Checks if a value is a number.                  |
| `boolean`| Checks if a value is a boolean.                 |
| `null`   | Checks if a value is null.                      |
| `exists` | Checks if a value exists.                       |
| `date`   | Checks if a value is a valid date string.       |

These assertions provide a wide range of options to validate different aspects of the API response, allowing you to ensure the correctness and integrity of the data and behavior. You can select the appropriate assertion based on the specific validation requirements of your API test scenario.

</details>

<details>
<summary><b><code>exports</code> field</b></summary>
<br />

The `exports` field in `testkit` allows you to capture and store values from the API response of a stage for future reference within the test scenario. It provides a convenient way to extract specific data and make it accessible in subsequent stages of the test.

To use the `exports` field, you define key-value pairs where the keys represent the names of the exports (think of it as a variable), and the values define the JSON paths or expressions used to extract the desired data from the response.

Here's an example that demonstrates the usage of the `exports` field:

```yaml
- title: Fetches Todo items - GET
  GET: /todos/
  exports:
    todoItem: $.resp.json[0]._id
```

In the above example, the `exports` field captures the value of the `_id` property from the first element of the API response array. It assigns this value to the `todoItem` export. By capturing the `_id` value in the `todoItem` exports, you can access it in subsequent stages of the test scenario. This allows you to use the extracted data for further API requests, assertions, or any other necessary operations.

The `exports` field enables you to create a bridge between different stages within the test scenario, providing a way to pass relevant data between them. This can be particularly useful when you need to refer to specific values or dynamically generate inputs for subsequent API requests. Using the `exports` field, you can enhance the flexibility and modularity of your API tests, making them more robust and adaptable to different scenarios.

</details>

### What is JSONPath?

JSONPath is a powerful query language designed for navigating and extracting data from JSON documents. It provides a concise syntax that allows you to specify paths to specific elements within a JSON structure, facilitating data access and manipulation. In `testkit`, JSONPath expressions are extensively used to extract data for assertions and exports. To illustrate how JSONPath works, consider the following examples:

- `$.user.name`: This expression retrieves the name of a user from the top-level object in the JSON document.
- `$.todos[0].task`: This expression accesses the task property of the first element in an array of todos.
- `$.todos[*].task.description`: This expression retrieves the description property of all tasks within the todos array.

The syntax of JSONPath expressions includes several key components:

| Component   | Description     |
|-------------|-----------------|
| Bracket notation  | Access elements within an array by providing the index within square brackets (`[]`). |
| Wildcard          | Match any element at the current level, allowing retrieval of all elements of that level (`*`). |
| Recursive descent | Enable searching for elements at any depth within the JSON structure, including nested objects and arrays (`..`). |
| Filters           | Apply conditions or filters to select specific elements based on certain criteria (`[?]`). |

By employing JSONPath expressions, you can precisely pinpoint the desired data within a JSON structure. These expressions play a vital role in `testkit` facilitating the extraction of data for performing assertions and capturing exports during the testing process.

<br />

> [!NOTE]
>
> To learn more about JSONPaths, please take a look at the [official docs](https://github.com/json-path/JsonPath/blob/master/README.md).

### Referencing Values and Dynamic Inputs for Subsequent API Requests

The `exports` field in `testkit` not only allows you to capture values from the API response but also provides a powerful mechanism for referencing those values and dynamically generating inputs for subsequent API requests.

By capturing relevant data using the `exports` field, you can store it as an export and easily refer to it in the later stages of your test scenario. This capability becomes particularly useful when you need to access specific values extracted from the response and utilize them in subsequent API requests.

For example, let's say you retrieve an ID from an API response in one stage using the `exports` field:

```yaml
- title: Fetch User - GET
  GET: /users/1
  exports:
    userId: $.resp.body.id
```

To reference this `userId` export in a subsequent API request, you can use the `$.stages[n].<VAL>` syntax:

```yaml
- title: Update User - PUT
  PUT: /users/$.stages[0].userId
  json:
    name: 'John Doe'
```

In the above example, the `userId` captured in the first stage is accessed using the syntax `$.stages[0].userId`. `testkit` understands that it should substitute the reference with the corresponding value during execution.

You can also use relative references like `$.stages[-n]` which refers to the `exports` of the `nth` stage before the current stage.
Example:

```yaml
- title: deletes TODO items - DELETE
  DELETE: /todos/$.stages[-1].todoItem #-1 means one stage before me
  asserts:
    - string: $.resp.json.task
    - ok: $.resp.json.id == $.stages[-1].todoItem
```

By referencing specific values captured in previous stages, you can establish dependencies between different API requests and ensure seamless data flow throughout your test scenario. This flexibility allows you to build more comprehensive and realistic tests, simulating complex user interactions or workflows.

### Date Assertions

To make date assertions in `testkit` you'll need to provide the date string and the date format, like so:

```yaml
- title: Get User Profile - GET
  GET: /user/jon_doe
  asserts:
    - date: $.resp.json.createdAt %Y-%m-%d %H:%M:%S %Z
```

In the example above, we first provide a JSONPath to the date followed by the date's format.

<details>
<summary><b>More on the date format</b></summary>
<br />

Testkit uses the chrono crate's formatting tokens to represent different components of a date. Here are some commonly used formatting tokens:

| Token | Meaning                                     | Example            |
|------|----------------------------------------------|--------------------|
| `%Y` | Year with century as a decimal number.       | 2023               |
| `%m` | Month as a zero-padded decimal number.       | 07                 |
| `%b` or `%h` | Abbreviated month name.              | Jul                |
| `%B` | Full month name.                             | July               |
| `%d` | Day of the month as a zero-padded decimal number. | 03            |
| `%A` | Full weekday name.                           | Monday             |
| `%a` | Abbreviated weekday name.                    | Mon                |
| `%H` | Hour (00-23).                                | 14                 |
| `%I` | Hour (01-12).                                | 03                 |
| `%M` | Minute (00-59).                              | 59                 |
| `%S` | Second (00-59).                              | 45                 |
| `%p` | AM/PM designation for 12-hour clock.         | PM                 |
| `%Z` | Timezone offset or name.                     | UTC                |

</details>

<details>
<summary><b>Example dates and their formats</b></summary>
<br />

Here are some example dates and their correct formats:

| Date String                     | Format                     |
| ------------------------------- | -------------------------- |
| 2023-07-26                      | `%Y-%m-%d`                 |
| 2023-07-26 12:34:56 UTC         | `%Y-%m-%d %H:%M:%S %Z`     |
| 15 August, 1995, 03:45 PM UTC   | `%d %B, %Y, %I:%M %p %Z`   |
| Mon, 05 Dec 2022 11:05:30 UTC   | `%a, %d %b %Y %H:%M:%S %Z` |
| January 01, 2000 - 00:00:00 UTC | `%B %d, %Y - %H:%M:%S %Z`  |
| 1987/03/10 06:30 AM UTC         | `%Y/%m/%d %I:%M %p %Z`     |

In this table, the "Date String" column represents the example date string, and the "Format" column contains the corresponding format string to parse the given date string.

</details>

### Using Environment Variables

Testkit supports environment variables in two ways (`.env` file and CLI configuration). These approaches allow users to configure and customize their test scripts without exposing sensitive data and making it easier to switch between different environments and scenarios seamlessly.

### Configuring the Environment Variables

Using a `.env` file involves creating a text file named `.env` in the test script's directory and defining `KEY=VALUE` pairs for each environment variable. `testkit` automatically loads these variables from the `.env` file during test execution, like so:

```sh
APIURL=https://api.example.com
EMAIL=user@example.com
PASSWORD=mysecretpassword
USERNAME=myusername
APIKEY=mysecretapikey
```

Setting environment variables directly is done via the command line or the test environment, like so:

```sh
APIKEY=SECRETAPIKEY testkit test --file test.tk.yaml
```

### Utilizing the Environment Variables

To utilize environment variables in `testkit`, you can access them using the following syntax: `$.env.<VAL>`, where `<VAL>` represents the name of the specific environment variable you want to use. This allows you to easily reference and incorporate the values of these environment variables within your test scripts, enabling greater flexibility and adaptability without hardcoding sensitive information or configuration details. Here's an example:

```yaml
- title: Register
  POST: '$.env.APIURL/users'
  headers:
    Content-Type: application/json
    X-Requested-With: XMLHttpRequest
  json: '{"user":{"email":"$.env.EMAIL", "password":"$.env.PASSWORD", "username":"$.env.USERNAME"}}'
  asserts:
    - exists: $.resp.json.user
    - exists: $.resp.json.user.email
    - exists: $.resp.json.user.username
    - exists: $.resp.json.user.bio
    - exists: $.resp.json.user.image
    - exists: $.resp.json.user.token
```

In this example, `testkit` performs a `POST` request to the API URL specified in the environment variable `APIURL`. The user information for registration is taken from the environment variables `EMAIL`, `PASSWORD`, and `USERNAME`, allowing for easy customization and reusability of the test script across different environments.

## Contributing and Help

To contribute to the development of this project or request help from the community and our team, kindly do any of the following:
- Read our [Contributors Guide](https://github.com/apitoolkit/.github/blob/main/CONTRIBUTING.md).
- Join our community [Discord Server](https://apitoolkit.io/discord?utm_campaign=devrel&utm_medium=github&utm_source=testkit_readme).
- Create a [new issue](https://github.com/apitoolkit/testkit/issues/new/choose) in this repository.

## License

This repository is published under the [MIT](LICENSE) license.

---

<div align="center">
    
<a href="https://apitoolkit.io?utm_campaign=devrel&utm_medium=github&utm_source=testkit_readme" target="_blank" rel="noopener noreferrer"><img src="https://github.com/apitoolkit/.github/blob/main/images/icon.png?raw=true" width="40" /></a>

</div>
