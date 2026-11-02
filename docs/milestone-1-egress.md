# Milestone 1 — guarded egress

Milestone 1 implements an authenticated loopback HTTP forward proxy and opaque HTTPS CONNECT, a shared authorization path, SQLite admission audit, live policy reload, process isolation and new-write/export redaction. Milestone 2 scanners remain blocked.

## Supported boundary

Every production HTTP worker request reloads the registered policy, checks program/tool permission, URL scope, exclusions, ports and paths, resolves all addresses, checks resolved-IP restrictions, and connects to the selected validated address without resolving the hostname again. Public DNS answers inherit only the scoped hostname's HTTP permission, never host-wide scan permission. An optional `egress.resolved_ip_ranges` list can further restrict every DNS answer.

Private/loopback destinations need both `scan.allow_private: true` and an explicit matching IP/CIDR in scope or `egress.private_networks`. The flag alone is insufficient for a DNS name resolving privately. Link-local metadata addresses, multicast, unspecified and reserved destinations stay denied. The broker uses the operating system resolver; external network DNS and direct sockets are denied by process isolation; offline host data is not network DNS. See [Phase A DNS details](phase-a-hardening.md).

The worker can connect directly through this same guard or explicitly route through the proxy. A caller constructing a standalone `Client(policy)` without workspace context gets static policy checks only; production scan, recheck, account-boundary and orchestration entry points supply workspace context and receive live reload and audit.

## Proxy behavior

- Listens on IPv4 loopback only, with a random per-session Basic proxy credential held in memory.
- Supports GET, HEAD and OPTIONS over plain HTTP. Other methods are denied. State-changing requests are not enabled by this milestone.
- Validates absolute request URL and Host agreement; rejects ambiguous framing and strips hop-by-hop/proxy credentials before forwarding.
- Injects the configured user-agent and researcher identification headers for HTTP. Profile credentials are not stored or logged. Plain HTTP credential forwarding requires an explicitly origin-bound session; the CLI proxy starts anonymously.
- CONNECT admits a complete HTTPS origin only. Path-specific scope or HTTPS exclusions cause denial because encrypted paths cannot be inspected without TLS interception. Required identification headers also cause denial unless a trusted launcher supplies the required flags.
- CONNECT uses a validated pinned TCP connection and does not intercept TLS, replace certificates or disable TLS verification.
- A CONNECT audit entry describes a tunnel, not every encrypted HTTP request inside it. Its bytes and lifetime are bounded. Application request counting, paths, header injection and HTTP/2 origin behavior inside opaque TLS cannot be inspected. Do not interpret the tunnel counter as an HTTP request counter.
- Every admitted/denied proxy request is recorded without URL paths, query strings, payloads, cookies, authorization headers or proxy credentials.

New HTTP admissions read current policy. A version/hash check after resolution and before connection refuses stale permits. Active requests/tunnels are closed on a policy change, checked every 100 ms; already transmitted bytes cannot be recalled. Even direct SQL policy edits change the canonical hash and are noticed. Scope synchronization from platforms remains milestone 11.

## Shared limits

Within one broker/worker process, direct guarded clients and proxy sessions share per-program/hostname pacing, target concurrency, a process-wide concurrency gate and per-run admission counts. For HTTPS, pacing is tunnel admission rate and the counter counts CONNECT tunnels, not requests inside them. This is a sequential pacing implementation, not milestone 5's durable token-bucket queue. Independent CLI processes do not yet share a durable global budget.

Optional program configuration:

```json
{
  "egress": {
    "global_concurrency": 4,
    "target_concurrency": 1,
    "resolved_ip_ranges": [],
    "private_networks": [],
    "tunnel_seconds": 15,
    "tunnel_bytes": 2097152
  }
}
```

Concurrency bounds are 1–16 globally and 1–8 per target. Tunnel limits are 1–60 seconds and 1024–8388608 bytes, counting both directions. Plain HTTP request/time/response/rate limits apply. For HTTPS this is tunnel admission rate: encrypted request counts, methods and paths are invisible; request behavior inside tunnels is bounded only by pinned templates and fixed tool flags. Refused admission does not contact the destination. Broker sessions expire under the program's run-time/request budgets; restarting creates a new explicit run.

## Process isolation by OS

| OS | Mechanism | Current result |
| --- | --- | --- |
| macOS | Installed `/usr/bin/sandbox-exec`, with network denied except IPv4 TCP to the loopback proxy port; Mach service lookup is denied to prevent service-delegated networking | Supported only after runtime self-test |
| Linux | No verified namespace/container/relay backend is implemented | Fail closed before launching external tools |
| Windows | No verified WFP/container backend is implemented | Fail closed before launching external tools |

The macOS self-test proves designated proxy TCP access works and separate direct TCP, UDP and a spawned child's direct connection are denied. A proxy-ignoring process was exercised against a local listener and blocked by the OS; a real sandboxed curl request succeeded through the proxy. Proxy environment variables alone are never considered isolation. No sudo, host firewall changes, network-interface changes or automatic installation are used.

Only trusted installed tools are in scope for this launcher. The profile is network confinement, not a general filesystem sandbox for malicious programs. Inherited descriptors are closed, and the child environment is reduced: no inherited API tokens, cookies, proxy bypass variables or language injection settings. The proxy credential is supplied in the child environment, never command arguments or persisted run configuration. Output is bounded in memory; raw stderr is not logged. Temporary scanner-owned capture files are not published as evidence and remain in a private temporary directory until cleanup.

An OS-denied raw socket attempt never reaches the broker. It is prevented, not reconstructed into a fabricated HTTP audit row. The broker audits HTTP/CONNECT admissions; the launcher records failure/skip state. No claim is made that unprivileged Python can record every denied kernel syscall with host/port attribution.

### Existing external tools

- curl now runs only through the authenticated proxy and verified process backend. Direct-resolution/proxy-bypass flags are removed; researcher headers and verified TLS remain.
- Nmap cannot use an HTTP proxy for port/service/OS/UDP scanning. Its network execution is therefore skipped instead of bypassing this milestone's guard. Parsers, existing inventory, planning and mocked adapter tests remain.
- Subfinder is also isolated. Provider requests must pass scope; no implicit exception is granted to public discovery APIs. Explicit provider/service permissions are deferred to milestone 4, so normal provider-backed discovery may be denied under a target-only policy. The fixture executable still verifies bounded launch and parsing.
- SearchSploit runs with all networking denied and performs local searches only.
- httpx, Nuclei, WhatWeb and WPScan remain blocked pending milestone 2's guarded adapters. Saved-result import continues to work.

## Commands

After registering an authorized program, put a random proxy credential of at least 24 characters into `EXPERTOOL_PROXY_TOKEN` in the shell environment. Do not put it in a policy file or command argument.

```sh
python3 -m expertool --db lab.db egress-proxy --program lab --tool http --port 8766
```

In another terminal with the same environment value:

```sh
python3 -m expertool --db lab.db scan --program lab --url http://127.0.0.1:8901/ --proxy-url http://127.0.0.1:8766 --no-crawl
python3 -m expertool --db lab.db egress-log --program lab
```

Use the bundled `examples/lab.py` fixture and lab policy for local testing. The explicit worker proxy mode supports anonymous HTTP and permitted full-origin HTTPS; origin-bound authenticated plain HTTP proxy sessions require the Python session API. Direct production worker requests still use the live guard and are audited.

To apply a manually reviewed local policy revision:

```sh
python3 -m expertool --db lab.db program-update --name lab --file reviewed-policy.json
```

For immediate program-wide revocation, set `automation.allowed` to false in that reviewed policy. `program-update` is an explicit local administrative operation, not automatic platform scope approval. New platform assets are not fetched or enabled by this milestone.

## Audit and redaction

`egress_events` records program, host, port, admission decision, fixed reason code, tool, run id, policy hash, selected IP, transport and timestamp. `egress-log` and the workspace snapshot expose redacted entries; the snapshot returns the latest 1000 while SQLite retains history. Invalid/unauthenticated requests can have no known host or policy hash. An allowed admission records authorization, not guaranteed network success.

New evidence, metadata, run configs/results, validation entries and exports pass a central sanitizer. It strips registered runtime credentials (including bearer/cookie components), recognized token formats, credential fields and sensitive query parameter values. Proxy logs never capture full request URLs or headers. Unknown unlabeled secrets cannot be reliably classified; no raw response capture is persisted by this milestone. Old on-disk data is not rewritten automatically; old exports/snapshots are sanitized on read, but previously stored raw data needs a separate reviewed cleanup if present.

## Acceptance evidence

The test suite includes allowed HTTP forwarding/header injection, CONNECT relay, a real HTTPS request with a trusted local fixture CA and certificate verification, out-of-scope/excluded hosts, all-answer IP rejection, DNS-once pinning, metadata/private destination refusal, policy revocation of both new requests and an existing tunnel, worker proxy routing, shared concurrency, authentication/framing refusal, redacted storage/reports, unsupported-OS refusal, real macOS proxy-bypass blocking, and real guarded curl. All destinations are local fixtures or mocked DNS answers; no public target is scanned.

The original 60 tests remain in the full suite. The response-handling fix also corrects a pre-existing edge case where reading a Content-Length-complete response tried to adjust an already closed socket.

Final verification: the full suite includes the original 60 regression tests plus the new egress acceptance tests. The CLI was also exercised end to end: proxy startup, routed scan, committed policy update, immediate denial, and redacted audit export. No public target was contacted.

Phase A adds [hash-chain verification, provenance and adversarial hardening](phase-a-hardening.md). Historical audit rows are explicitly marked as legacy backfill.
