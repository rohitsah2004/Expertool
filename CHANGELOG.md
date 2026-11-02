# Changelog

## R3–R4 — passthrough and constrained program CAs

- Added explicitly approved blind CONNECT for out-of-scope third parties, with all-answer public-address checks, pinned IPv4, caps, revocation and distinct audit events. No CA use or injection in blind tunnels.
- Added per-program critical DNS/IP name constraints, scope binding, explicit rotation/public-only retirement and optional environment-passphrase key encryption. Updated CA CLI migration and trust-removal guidance.
- Refused unreviewed wildcard passthrough roots and unrepresentable certificate-scope combinations; runtime request scope remains mandatory.
- R5 reuse evaluation retains connection-close and identity encoding until fresh-permit/framing guarantees are demonstrated. Blind relay failures close without injecting HTTP after CONNECT acknowledgement.
- Final macOS verification: 180 passed, 0 skipped, 0 failed, including all four real-scanner local tests. No W2/W3 implementation, installs or trust changes.

## R2 — shared guarded send

- Extracted manual request sending into RequestSpec/ResponseSpec and send_guarded; interception delegates network safety and forwarding to that API.
- Added format-3 audit source metadata with prior-format verification retained, direct send regressions, and fixed-reason error reporting. No history or replay UI added.

## R1 — redaction correctness

- Replaced exact-key regex matching with normalized secret-key matching and a small typed false-positive allowlist. Expanded URL/form/OAuth and header redaction.
- Preserved JSON/JSONL framing and typed literals; added ordered-header and encoded-form body handling.
- Restricted cookie/credential registration and bounded recall with entry/byte limits and access LRU. Key/pattern layers remain the primary defense.
- Added 88 synthetic fixtures, generated JSON property checks, cache/boundary tests and a 64-KiB offline microbenchmark. On macOS: 162 passed, 0 skipped, 0 failed; all measured 64-KiB benchmark means were under 1 ms. R2–R5 and W2/W3 are not started.

## Workbench W1 — manual interception

- Added a separate authenticated loopback manual listener with scoped TLS termination, per-request guard checks, pinned IPv4 and verified upstream TLS.
- Added explicit CA creation/public-only export/destruction, private key permissions and active-listener leases. Browser/OS trust is never installed automatically.
- Added manual-only opt-in and documented reviewer/timestamp approval for state-changing methods; scanner method limits remain unchanged.
- Added version-2 audit metadata for method, path hash and injected-header names without invalidating prior event hashes/checkpoints; surfaced manual audit details in Runs.
- Refused HTTP/2, upgrades/WebSockets, out-of-scope passthrough and raw capture. Added stop-state checks and bounded local policy-write retry for shared-cache read contention.
- All 153 tests pass with all four real-scanner lab tests enabled; Python/JavaScript syntax checks pass. No public traffic or trust installation. W2–W6 have not started.

## Phase A — smoke-test hardening

- Added scanner entry-point path/SHA256/version provenance, offline isolated version probes, tested-version comparison and optional per-program refusal of untested versions.
- Added configurable 30-day manifest/database age warnings and report date/basis disclosure.
- Validated all DNS answers before selecting IPv4 routes; refused ambiguous IP notation, mapped/zone forms and IPv6-only routing. Unreadable policy state explicitly revokes connections.
- Added bounded header parsing, total slow-client deadline and adversarial HTTP/CONNECT coverage. HTTPS limits are documented as tunnel admission rate.
- Added transactional hash-linked egress events, disclosed legacy backfill and checkpoint-aware audit verification. All 129 tests pass with four real-scanner lab tests enabled; CLI checkpoint acceptance also passes. No Phase B–E work started.

## Milestone 2 follow-up — YAML import and real binaries

- Added offline YAML-to-pinned-subset import with bounded safe parsing, duplicate/alias/tag rejection, atomic batches and review hashes. Added a synthetic exposed Git-config lab check.
- Fixed real httpx loopback proxy configuration, WhatWeb proxy authentication/pre-proxy DNS, Ruby interpreter selection, and WPScan offline database copying and finding exit code. Scope/isolation remain mandatory.
- Added opt-in real-binary loopback regression tests and recorded a user-authorized root-only HTTPS smoke test of an explicitly authorized owner-controlled target. No vulnerability is claimed from reachability checks.
- Installation was explicitly approved; no sudo or automatic installation path was introduced. All 109 tests pass with the four real-binary tests enabled, plus CLI import acceptance.

## Milestone 2 — live guarded scanners

- Added opt-in httpx, Nuclei, WhatWeb and WPScan commands and proactive pipeline integration, with passive defaults and no arbitrary CLI flags.
- Added SHA256-pinned, restricted GET/HEAD Nuclei templates and tag/severity policies. Matches remain candidates.
- Added isolated scanner configuration, memory-only proxy setup, per-session policy invalidation and scoped result validation. Missing tools/isolation are skipped; refused policy is blocked.
- Preserved saved-output imports and fixed structured JSON/JSONL redaction without corrupting output framing.
- Added mocked-executable integrations through the actual local proxy/OS sandbox and regression tests. No real vendor scanner binary was installed or public target scanned.
- Milestone 3 is not started. Full upstream YAML templates and authenticated external scans remain out of scope.

## Milestone 1 — guarded egress

- Added an authenticated loopback HTTP/CONNECT proxy, pinned DNS destinations, full-origin-only HTTPS admission and shared process limits.
- Added per-request committed policy reload, policy hashes, explicit local updates and active-connection revocation polling.
- Added SQLite egress admission audit and central new-write/export redaction.
- Added verified macOS process network confinement; unsupported hosts refuse external launch. Existing network tools cannot fall back to unrestricted execution.
- Added proxy/policy/audit CLI commands and optional built-in worker proxy routing. Kept scope imports and saved-result import intact.
- Fixed a Content-Length response socket-close edge case found by proxy tests.
- Milestone 2 tool enablement is intentionally not started. Opaque TLS cannot enforce path-specific rules; such tunnels are denied. Durable cross-process budgets remain milestone 5.
