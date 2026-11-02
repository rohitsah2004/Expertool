# Live assessments

**Current execution boundary:** see [Milestone 1 guarded egress](milestone-1-egress.md). Production HTTP requests reload policy and are audited. External execution requires verified process isolation; Nmap raw scanning is skipped, and Subfinder has no automatic provider-scope exemptions.

Expertool now executes bounded read-only HTTP assessments, HTML crawling, custom GET checks, authenticated comparisons, controlled two-account canary checks, passive Subfinder discovery, and recurring anonymous HTTP assessments. It stores execution and validation history in the same SQLite database used by the dashboard.

## Try everything locally

The bundled lab is deliberately weak and binds only to loopback. No external targets are required. Start it in one terminal:

```sh
python3 examples/lab.py
```

In another terminal, register the lab once and scan it:

```sh
python3 -m expertool --db lab.db program-add --name lab --file examples/lab-program.json
python3 -m expertool --db lab.db scan --program lab --url http://127.0.0.1:8901/ --checks examples/checks.json
python3 -m expertool --db lab.db show --program lab
python3 -m expertool --db lab.db serve
```

Open http://127.0.0.1:8765 to review findings and the **Runs & schedules** view. The lab's missing header/cookie settings are configuration observations; the fixture marker is an informational demonstration of custom checks.

## Authentication-aware assessments

Profiles contain environment variable names, not credentials. Supported headers are Authorization, Cookie, and X-API-Key. Each profile is bound to one exact scheme/hostname/port origin. Values are read at execution time and not saved in configuration or raw captures. Credentialed requests require HTTPS, except explicitly enabled loopback fixtures. Automatic redirects do not forward credentials.

Use these deliberately fake lab values:

```sh
export EXPERTOOL_LAB_OWNER_AUTH='Bearer lab-owner'
export EXPERTOOL_LAB_OTHER_AUTH='Bearer lab-other'
export EXPERTOOL_LAB_CANARY='EXPERTOOL_OWNED_CANARY_2026'
python3 -m expertool --db lab.db scan --program lab --url http://127.0.0.1:8901/protected --auth-profile examples/lab-owner.json --compare-auth --no-crawl
```

The comparison stores authenticated and anonymous status codes and whether body hashes differ. Differences alone never create an authorization vulnerability finding. Login flows, browser sessions, token refresh and JavaScript rendering are not automated.

### Validate a controlled account boundary

Create a dedicated harmless canary in an object owned by account A. Confirm the program permits testing this account boundary, and that account B must not be able to read it. Supply both controlled account profiles and the marker through an environment variable. The tool makes two GET requests; it does not enumerate object IDs, change permissions, or mutate objects.

The lab intentionally fails this boundary:

```sh
python3 -m expertool --db lab.db access-check --program lab --url http://127.0.0.1:8901/private-canary --owner-profile examples/lab-owner.json --other-profile examples/lab-other.json --marker-env EXPERTOOL_LAB_CANARY --expect-denied
```

A marker observed in both successful responses creates a high-severity **candidate** with a `reproduced` validation entry. The marker value and credentials are omitted from stored evidence. A hash and boolean results are retained. The user's declaration of expected privacy is an essential precondition; intentionally shared objects invalidate this interpretation.

To simulate remediation, stop the lab, restart with `FIX_BOUNDARY=1 python3 examples/lab.py`, and repeat the access check. Validation history then records `not-reproduced`; the original finding and review decision remain available.

## Custom executable checks

`--checks` accepts an array of at most 50 JSON definitions, separate from the reference-only technique catalog. See `examples/checks.json`.

Each definition has a unique simple `id`, `name`, `severity`, origin-relative `path`, and `match`. The match can combine an integer `status`, a `header` name-to-substring map, and a `body_contains` literal. Conditions are combined with AND. Checks perform GET only and use the same scope, credential, rate and request budgets as crawling. Matching a string or status does not prove vulnerability impact. Response bodies and cookie values are not stored.

There is no shell execution, arbitrary Python, JavaScript evaluation, regex engine, destructive payload, or automatic template download in these definitions.

## Rechecks and validation

```sh
python3 -m expertool --db lab.db recheck --id FINDING_ID
python3 -m expertool --db lab.db recheck --id CUSTOM_FINDING_ID --checks examples/checks.json
```

Replace the ID placeholders with actual IDs from `show` or the dashboard. Supply the same auth profile where required. Built-in header/cookie conditions and custom checks support rechecking. Validation outcomes are `reproduced`, `not-reproduced`, or `inconclusive`. They are separate from hunter review states. For two-account findings, repeat `access-check`. Imported Nuclei findings need their original reviewed template and are not automatically exploited or revalidated by this implementation.

## Scheduling

```sh
python3 -m expertool --db lab.db schedule-add --program lab --url http://127.0.0.1:8901/ --interval 3600
python3 -m expertool --db lab.db schedules
python3 -m expertool --db lab.db worker --once
python3 -m expertool --db lab.db worker
```

The first run is due immediately. `worker --once` claims at most one due schedule and exits. The persistent worker polls until Ctrl+C. It must remain running for recurring execution; schedules are not installed into the operating system. Intervals are elapsed seconds, independent of timezone. A run consumes its interval even when it fails. Leases prevent simultaneous claims of the same schedule and expire after a worker crash. Missed intervals are coalesced rather than replayed.

Schedules run anonymous assessments; programs with proactive orchestration enabled also execute their configured tool pipeline. Credentials and custom definitions are not persisted in schedule rows. Disable with `schedule-set --id ID --enabled no`. Concurrent independent runs have independent rate budgets; use one worker to serialize scheduled work.

## External tools

See the [target-driven assessment guide](proactive-assessments.md) for automatic Nmap/curl/WhatWeb/WPScan/SearchSploit selection and their separate policy requirements.

```sh
python3 -m expertool tools
python3 -m expertool --db assessment.db discover --program YOUR_PROGRAM --domain YOUR_APPROVED_DOMAIN
```

`discover` launches an already installed Subfinder binary from PATH with passive mode, JSON output, rate limit, automatic update checks disabled, and bounded process runtime/output. It uses argument arrays without a shell. Excluded/out-of-scope discoveries are counted and discarded before storage. Installation and API/provider configuration are managed outside Expertool. The executable must be trusted.

External httpx and Nuclei results can be imported, but launching those engines is not implemented: their internal requests and arbitrary template behavior are not covered by the built-in worker's per-request guard. The built-in HTTP worker performs live probing instead. No external tool is automatically installed. Subfinder process integration is tested with a local fixture executable, not a real provider-backed run.

## Scope and execution budgets

Every live request requires a program with `authorized: true` and `active` in `allowed_modes`. Existing passive-only programs continue to reject live scans. The optional `scan` policy supports:

| Setting | Default | Range / meaning |
| --- | --- | --- |
| `max_requests` | 30 | 1–500, all GETs including comparison requests |
| `max_depth` | 2 | 0–5, HTML link depth |
| `rate_per_second` | 1 | 0.1–10, per sequential run |
| `timeout` | 5 | 0.1–30 seconds per request / DNS operation |
| `max_seconds` | 120 | 1–600 seconds per HTTP run |
| `max_response_bytes` | 262144 | 1024–2097152 bytes per response |
| `ports` | `[80,443]` | Allowed TCP destination ports |
| `allow_private` | false | Explicit opt-in for loopback/private-network fixtures |
| `path_prefixes` | `["/"]` | Allowed path boundaries |
| `excluded_paths` | `[]` | Excluded path boundaries |

DNS answers are validated before a connection, and the worker connects directly to the validated address while retaining TLS hostname verification. Non-public addresses are blocked by default; link-local, multicast and unspecified destinations remain blocked even with private networks enabled. Environment proxy variables are ignored.

Crawling stays on seed origins. Scope is checked for every discovered URL and redirect before another GET. Forms are inventoried but never submitted. Common logout/delete paths are skipped, but an application's GET handler can still have side effects; program rules remain authoritative. Encoded traversal paths are rejected. The current host model supports DNS names and IPv4, not literal IPv6 targets. Only UTF-8/identity HTML is parsed; no browser rendering or script execution is performed.

The policy bounds network execution, not arbitrarily large existing SQLite/import datasets. Query strings and user-supplied URLs may be sensitive; provide assessment-specific URLs and redacted imports. Redaction of exact auth-header values is not a comprehensive secret scanner.

## Coverage boundary

The implemented detectors cover HTTP header/cookie posture, custom literal/status/header conditions, and explicitly configured two-account canary boundaries. There is no claim of comprehensive CVE detection, automatic SQL injection/XSS/SSRF testing, browser exploitation, or arbitrary exploit-chain validation. The 24-family knowledge catalog remains a reference catalog. These capabilities need class-specific detectors and lab validation before claiming coverage.
