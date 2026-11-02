# Expertool

**Milestone 2:** [live guarded scanners](docs/milestone-2-scanners.md). httpx, Nuclei, WhatWeb and WPScan can be explicitly enabled through the proxy and verified process sandbox. Nuclei requires pinned reviewed templates; scanner matches remain candidates. No auto-installation or unguarded launch.

**Milestone 1:** [guarded egress operating guide](docs/milestone-1-egress.md). Production HTTP requests now reload policy and record admissions. External tools require verified process isolation; Nmap network execution is skipped because it cannot use the HTTP proxy. [Changelog](CHANGELOG.md).

Local bug bounty assessment workspace with a source-backed technique catalog, program-scoped imports, evidence storage, review states, and Markdown reporting. Python 3.10+, standard library only.

**Current status:** local dashboard and CLI with scoped live HTTP assessments, HTML crawling, executable custom GET checks, authentication profiles, two-account canary validation, finding rechecks, persistent schedules/run history, and a process-isolated Subfinder launcher (provider requests still require scoped permissions). Saved imports and the 24-family reference catalog remain available.

**Scope-first roadmap:** [scope management](docs/scope-management.md) and [implementation roadmap](docs/roadmap.md). Imported scopes start disabled for review. Unguarded WhatWeb/WPScan execution is blocked; the former external HTTP opt-in no longer bypasses scope enforcement.

**Proactive tool selection:** [target-driven assessment guide](docs/proactive-assessments.md). A configured target drives guarded curl and local SearchSploit research. Nmap is skipped because raw scans cannot use the HTTP proxy; httpx/Nuclei/WhatWeb/WPScan use the opt-in milestone 2 adapters. Installed tools and program permissions determine which stages run.

**Start here for live execution:** [local lab and live-assessment guide](docs/live-assessments.md), with a runnable loopback lab, authentication examples, scheduling, budgets, and exact detector coverage.

Detection currently covers header/cookie posture, custom response conditions, and configured account boundaries. Broad CVE scanning, automatic injection testing, browser exploitation, and external httpx/Nuclei execution are not implemented.

## Open the review dashboard

After creating/importing a workspace with the commands below:

```sh
python3 -m expertool --db demo.db serve
```

Open **http://127.0.0.1:8765** in your browser. Use `serve --port 8766` to choose another port. Stop the server with Ctrl+C.

The dashboard uses the same database as the CLI. Select a program, filter findings by state/severity or search their text, and open **Review** to inspect evidence. **Mark candidate**, **Dismiss**, and **Confirm finding** persist review decisions. Asset inventory shows imported metadata observations; Program scope shows approved hostname rules. **Export report** downloads Markdown. Use **Refresh** after CLI imports.

An empty database displays setup instructions. Program registration and imports remain CLI operations. The dashboard is a local single-user interface bound to loopback, with same-origin/token checks on review updates. It has no remote hosting or multi-user authentication. Assessment text is rendered as plain text, and no third-party fonts, scripts or analytics are loaded.

## Try the complete offline workflow

Run from this directory. These commands use reserved example domains and local fixtures; no requests are sent.

```sh
python3 -m expertool --db demo.db program-add --name demo --file examples/demo-program.json
python3 -m expertool --db demo.db import --program demo --file examples/recon.jsonl
python3 -m expertool --db demo.db import --program demo --format headers --file examples/headers.jsonl
python3 -m expertool --db demo.db show --program demo
python3 -m expertool --db demo.db review --id 1 --state dismissed
python3 -m expertool --db demo.db report --program demo
```

Program registration is create-only; registering the same name again fails. Repeating imports deduplicates assets by normalized URL and findings by program, URL, and check ID. Existing evidence and review states are preserved, not overwritten. This version retains the first observation rather than scan history.

Distinct metadata observations and source labels are retained separately; repeated identical observations are deduplicated. Existing database files gain the observations table automatically without deleting previous data. Earlier imports have no backfilled metadata.

`report` writes Markdown to stdout. To save it:

```sh
python3 -m expertool --db demo.db report --program demo > demo-report.md
```

## Import formats

### Native saved tool output

Use the existing `demo` program above, or create one first. All bundled examples are synthetic fixtures, not findings from live targets.

```sh
python3 -m expertool --db demo.db import --program demo --format subfinder-json --file examples/subfinder.jsonl
python3 -m expertool --db demo.db import --program demo --format httpx --file examples/httpx.jsonl
python3 -m expertool --db demo.db import --program demo --format nuclei --file examples/nuclei.jsonl
python3 -m expertool --db demo.db show --program demo
```

| Format | Input | Stored result |
| --- | --- | --- |
| `subfinder` | Plain hostname per line; no banners or CSV | `dns://hostname` discovery assets |
| `subfinder-json` | JSONL with `host`, optional source metadata | DNS assets and source observations |
| `httpx` | ProjectDiscovery JSONL with `url` | HTTP assets and selected service metadata |
| `nuclei` | HTTP JSONL events with template ID, info, matched URL | Candidate findings and match metadata |

DNS discoveries do not establish that HTTPS or any other service is running. httpx probe failures are retained as observations, not vulnerabilities. Redirect destinations in `final_url` remain metadata; they are not automatically added to scope or imported as assets.

The Nuclei reader accepts HTTP events only. It prefers `matched-at`, then `url`, then `host`, and requires an explicit HTTP(S) URL. An explicit false `matcher-status` or nonempty error produces no finding. Omitted matcher status is treated as a match for ordinary match-only output. Unknown severity becomes informational with the reported value preserved. Different named matchers/extractors within a template remain distinct findings.

Native imports select metadata rather than copying whole captures. Requests, response bodies, headers, curl commands, and extracted values are not imported. Template metadata, URLs, titles and errors can still be sensitive; this is not a general-purpose secret redactor. Native adapters are tested with schema-shaped fixtures; installed tool binaries and arbitrary historical versions have not been tested.

Tool format references: [Subfinder output](https://github.com/projectdiscovery/subfinder/blob/dev/pkg/runner/outputter.go), [httpx result structure](https://github.com/projectdiscovery/httpx/blob/main/runner/types.go), [Nuclei result events](https://github.com/projectdiscovery/nuclei/blob/main/pkg/output/output.go). These readers import data only. A separate `discover` command can execute installed Subfinder; see the live guide.

### Normalized records and saved headers

One JSON object per line. Blank lines are ignored. The entire batch fails without partial writes if any record is malformed or outside the registered program scope.

Normalized records use `url` and an optional `findings` array:

```json
{"url":"https://api.example.com/v1/","findings":[{"check_id":"custom.example","title":"Example candidate","severity":"info","evidence":"Redacted reproduction evidence"}]}
```

Severity values: `info`, `low`, `medium`, `high`, `critical`. All imported findings start as `candidate`; confirmation is an explicit hunter decision. `--source` labels where an import came from and defaults to the selected format. Optional `metadata` objects are retained in observations. Normalized records use our own schema; the native readers above handle vendor output.

Saved-header records use `url` and a string-to-string `headers` object, as shown in `examples/headers.jsonl`. The analyzer checks missing HSTS on HTTPS and missing/incorrect `X-Content-Type-Options: nosniff`. It stores informational observations without raw header values. It does not fully validate HSTS syntax or establish an exploitable vulnerability. Headers must be combined or selected before import if the capture contains repeated names.

Storage is a local, unencrypted SQLite file. Supply redacted evidence and URLs; normalized imports preserve their evidence text and URL query strings. Assessment files should remain private.

## Run

From this directory:

```sh
python3 -m expertool validate
python3 -m expertool catalog --search authorization
python3 -m unittest discover -s tests -v
```

Copy `examples/program.json` to your own program file. Set actual authorized hostname rules, exclusions, and allowed modes. Record `authorized: true` only for an assessment you are authorized to perform. Then:

```sh
python3 -m expertool plan --program my-program.json --target api.example.com
```

The command prints a plan; it never contacts the target. Active entries are marked blocked unless the program explicitly allows active mode. A planned task is not an implemented check.

Scope currently supports exact hostnames and `*.example.com` (subdomains only). Exclusions override inclusions. Path-specific and port-specific scope is rejected rather than broadened. Program authorization is a user declaration, not independently verified permission.

## Add your knowledge

Copy `data/techniques.json`, add entries with a unique `id`, `name`, `category`, `mode`, `prerequisites`, `evidence`, and HTTPS `sources`. Modes are `passive`, `active`, or `manual`.

```sh
python3 -m expertool --catalog my-techniques.json validate
python3 -m expertool --catalog my-techniques.json catalog --search api
```

Custom catalogs are data, not executable plugins. Future execution adapters will be separate, reviewed modules. The initial entries are broad technique families, not an exhaustive collection of tactics or exploit variants.

See [research register and architecture](docs/sources.md) for reviewed repositories and subsequent milestones. Live scans additionally enforce configured ports and path boundaries. See the live guide for execution and detector coverage.

YAML templates can now be admitted offline with `template-import`; see [the importer and real-binary verification guide](docs/template-import.md). Real scanner tests are optional and loopback-only.

**Phase A hardening:** [tool provenance, freshness, DNS/proxy review and audit-chain verification](docs/phase-a-hardening.md). Use `tools --verify` and `audit-verify`; all traffic controls remain mandatory.

**Manual workbench W1:** [opt-in HTTP/1.1 interception, CA lifecycle and browser trust/removal](docs/workbench-w1.md). Separate listener; manual methods require explicit program approval. W2 request history and Repeater are not yet implemented.
