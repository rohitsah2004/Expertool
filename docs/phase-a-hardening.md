# Phase A — scanner provenance and egress hardening

This phase adds provenance and freshness disclosure, adversarial egress coverage and a hash-linked audit trail. Phases B–E have not started. No scanner, template or database is automatically installed or updated.

## Scanner identity and tested versions

Every new scanner run result includes `tool_identity`: tool name, resolved absolute executable path, SHA256 of the entry-point file, observed version/version string, and a version observation status. Missing or unreadable executables have null values and an explicit status. Disabled/out-of-scope runs do not execute a binary to discover its version. The stored null/unprobed version in those runs is deliberate; a historical version is never invented.

Once policy and target preflight pass, version probes run with a private HOME/cache and **no network permission**, including no proxy access. Probes have a five-second/64-KiB cap. Only a recognized version token is retained, not raw output. The executable hash is checked again after probing, before scanner launch. Entry-point hashing records provenance; it does not establish trust in Ruby gems, shared libraries, tool plugins or every dependency, and it is not an atomic executable-image attestation.

```sh
.venv/bin/python -m expertool tools --verify
```

This compares observed scanner versions to `data/tested-versions.json`. An unavailable or unknown version gets a structured warning. Default scanner execution warns and proceeds through the existing mandatory guard. To refuse untested/unobservable versions for a program:

```json
{"scanners":{"block_untested_versions":true,"stale_after_days":30}}
```

Merge these settings into the existing scanner configuration; they do not enable scanners or grant tool permission. Tested versions mean versions exercised by the local compatibility suite, not a blanket security endorsement. Editing the version list is a manual review action. Existing run history is not backfilled with speculative tool identities.

## Fingerprint/database dates

Nuclei results include the configured manifest's file date/age. WPScan results include the oldest date among copied fingerprint database JSON/text files and `dynamic_finders.yml`/`LICENSE`. Missing data, a future file date, and data older than `stale_after_days` produce warnings. The default staleness threshold is 30 days. These are warnings, not permission to download anything.

Markdown reports include **Fingerprint/database date: X**, age, and the date basis even when no findings were recorded. Dates are UTC. File modification times are observations, not trusted upstream release dates; copying or touching a file can make old content appear fresh. A new manifest does not prove its pinned checks cover current CVEs. The warning and basis must accompany interpretation of “no findings.”

## DNS and network boundary

The actor model is an installed trusted scanner handling untrusted target responses/template data. The sensitive sink is an outbound socket. Tools receive a private runtime environment and only the loopback proxy endpoint; the verified macOS Seatbelt profile denies other outbound TCP/UDP and Mach lookup, including inherited children. Unsupported OS backends fail closed. Version probes get no network exception.

| Component | Name resolution and actual routing |
| --- | --- |
| Guard / Python worker | Parent uses the OS resolver; every returned A and AAAA address is checked against exclusions and address restrictions. Any forbidden answer rejects the entire resolution. Only validated canonical IPv4 answers are dialed; no second hostname lookup is used for the destination connection. IPv6-only targets are refused. |
| httpx | Explicit proxy config arrives through an anonymous inherited pipe. Go/tool resolver attempts do not receive direct DNS/socket permission. Actual target HTTP/CONNECT admission and fresh DNS occur at the guard. Any vendor behavior requiring direct DNS fails closed. |
| Nuclei | Explicit proxy list arrives through an anonymous pipe; no default community templates, OAST, headless, code or DNS templates. Direct Go resolver/network attempts are OS-blocked; actual scoped connections resolve at the proxy. |
| WhatWeb | A trusted launcher supplies only a preflight-approved IPv4 metadata snapshot for the selected target and numeric proxy address. Its display-time `Resolv.getaddress` cannot look up an unknown name. This metadata does not authorize routing: the proxy independently re-resolves, validates and pins the connection. |
| WPScan | Explicit proxy settings stay in memory; curl/Ruby target requests and attempted metadata API calls encounter the same guard. DNS/direct socket attempts outside the proxy are OS-blocked. No out-of-scope provider exception is added. |

An offline `/etc/hosts` entry, IP literal, cached address or a value computed by a process is not a network DNS request. No sandbox can forbid a process from knowing such values. The enforced guarantee is that a child cannot send external DNS traffic or connect directly to an unvalidated destination; only guarded proxy admission can create a target connection. Tests exercise blocked UDP/TCP DNS sockets, system lookup failure for an unvalidated name, direct-child bypass, all-answer A/AAAA handling, rebinding/pinning, private and excluded addresses, and real tool compatibility. This is evidence for the exercised macOS backend and versions, not a promise about every untested resolver implementation.

Decimal/octal/hex and shortened IPv4 notations, trailing-dot request hosts, IPv4-mapped IPv6 and zone-qualified forms are refused at egress admission. All returned IPv6 answers are checked for scope/address policy, but not selected as routes by the IPv4-only backend. Scope configuration/import normalization remains separate from request admission.

## HTTP and opaque HTTPS limits

Plain HTTP remains GET/HEAD/OPTIONS only, with current scope/path checks, request budgets, identification injection, and proxy/hop-header stripping. Host must agree with the absolute URI. Duplicate or malformed Content-Length, any Transfer-Encoding, oversized headers and malformed authorities are refused. Headers have 8-KiB line and 32-KiB aggregate caps. Request lines have an 8-KiB admission limit. A three-second total request-line/header deadline prevents indefinite slow-client trickling. Each proxy session closes after one HTTP request; a keep-alive/pipelined authority switch cannot inherit an earlier permit.

**HTTPS uses tunnel admission rate.** The proxy sees host and port only. It cannot see HTTPS methods, paths, request counts, header values or HTTP/2 origin behavior. Request behavior inside tunnels is bounded only by reviewed/pinned templates and fixed tool flags, not per-request proxy inspection. Tunnels additionally have byte/lifetime/concurrency limits and revocation checks; those are transport bounds, not HTTP request counts. Full-origin HTTPS scope is required. A target with narrow HTTPS path constraints remains blocked.

Active policy changes or unreadable policy state revoke in-flight connections. Already transmitted bytes cannot be recalled. Redirects are never scope grants: the plain proxy does not follow them, and a new private/metadata destination is denied. An HTTPS vendor redirect still has to request a new CONNECT when it needs another origin; the broker cannot inspect application redirects inside an already permitted opaque tunnel.

## Tamper-evident audit chain

New `egress_events` rows include `prev_hash`, `event_hash`, and `chain_origin`. The event hash covers its previous hash plus canonical stored event fields, including row ID, timestamp and chain origin. Redaction happens before hashing. Inserts are serialized with `BEGIN IMMEDIATE`; independent SQLite writers cannot fork the chain. Verification reads a consistent transaction.

```sh
.venv/bin/python -m expertool --db scanners.db audit-verify
.venv/bin/python -m expertool --db scanners.db audit-verify --out audit-checkpoint.json
.venv/bin/python -m expertool --db scanners.db audit-verify --checkpoint audit-checkpoint.json
```

`--out` exclusively creates a checkpoint; it never overwrites one. A failed verification exits nonzero. The checkpoint contains row count, tail ID and tail hash. Retain it independently of the database and verify against it later. The chain is global across programs so per-program exports are not mistaken for complete chains.

Existing audit tables migrate atomically. Legacy rows are hashed with `chain_origin=legacy-backfill`, and the verifier discloses their count. This proves nothing about events before migration. Opening the database again does not repair missing or changed hashes. Editing a row or deleting an interior event breaks verification. An independent checkpoint detects deletion/truncation before its anchored tail. Without that checkpoint, deleting the tail or rewriting the entire chain can go undetected; this is tamper evidence, not immutable storage or a digital signature.

## Verification and decisions

Phase A tests cover scanner identity/hash/version parsing, block-before-launch for untested versions, missing/future/stale file dates, report disclosure, legacy migration, concurrent writes, redaction-before-hash, edit/delete/truncation detection, mixed A/AAAA/private/excluded answers, alternate IP encodings, OS DNS/direct socket denial, Host mismatch, duplicate hosts, keep-alive reuse, proxy-auth stripping, framing, header size/slow clients, metadata redirects and mid-transfer CONNECT revocation. The original regression suite and optional real-scanner loopback tests remain in use.

No public target scanning is needed for this phase. The existing smoke record is unchanged historical evidence. No bulk imports, approval workflow, change alerts, hunting helpers or benchmark framework has been added; those belong to later phases.

Final Phase A verification: **129 tests passed in 38.447 seconds**, with all four real-scanner loopback tests enabled and no skips. `tools --verify` recognized all four installed tested versions. CLI checkpoint creation/verification and simulated-truncation exit-status checks passed. Python compilation passed. No tools, templates or databases were installed or updated, and no public target scan was run during this phase.
