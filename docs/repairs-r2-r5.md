# Guarded-workbench repairs R2–R5

## R2: one guarded send

`expertool.send.send_guarded` accepts an immutable RequestSpec containing a method, absolute URL, ordered header pairs and body bytes. It performs manual method policy, current scope/address authorization, body caps, budget reservation, revocation checks, pinned IPv4 connection, verified upstream TLS, researcher-header injection and response caps. It returns status, ordered response headers, bytes, timings, injected header names, the permit/policy version and a truncation flag. Over-budget responses are refused, not silently truncated. It never retries or sends multiple requests.

The browser handler only parses/bounds the incoming wire message, invokes the shared sender with `source="browser"`, and serializes the response. A future replay caller must use this same API. Ordered input is not rewritten; ambiguous duplicate request headers remain refused, while repeated response headers are retained. Scanner behavior is unchanged. Authorization/credentials and bodies remain volatile and are not written to the audit trail.

Audit format 3 adds source and retains verification of format 1/2 hashes and checkpoints. A pre-send admission event and a post-response completion event distinguish permission to send from successful response completion. Certificate verification errors remain distinct from refusal/failure. Request-level scope, method and address checks still apply to intercepted TLS; the separate scanner proxy remains opaque and enforces tunnel admission rate.

R3 and R4 are not implemented by R2; R5 connection reuse remains deferred until the required repairs pass. W2/W3 are not part of these changes.

R2 verification on macOS: 169 passed, 0 skipped, 0 failed (49.872 seconds), including the four real-scanner loopback tests.

## R3: explicitly approved blind passthrough

`interception.passthrough` can be an approval object with `enabled`, `hosts`, `ports`, `approved_by` and timezone-aware `approved_at`. False remains the default. Example:

```json
{"enabled":true,"hosts":["accounts.google.com","*.gstatic.com"],"ports":[443],"approved_by":"reviewer","approved_at":"2026-11-01T12:00:00-06:00"}
```

This permits only the browser's blind CONNECT traffic to listed third parties. No certificate, TLS decryption, researcher header injection, credential injection, history or testing is performed there. The browser must verify those sites' certificates itself; the proxy cannot inspect methods, paths, state-changing actions, encrypted request counts or credentials inside the tunnel. Program rules must permit this traffic. It uses tunnel admission rate/counts, lifetime/byte caps, shared concurrency and active policy revocation.

Out-of-scope unlisted/excluded hosts remain refused. All A/AAAA answers pass the same address checks, and private/special/mapped addresses are always denied even when the assessment has loopback/private exceptions. The selected public IPv4 is pinned. No failed in-scope path, port, DNS or method check can fall back to passthrough. Audit transport/reason `passthrough` marks blind traffic distinctly and contains no tunneled content. New startup warnings flag wildcards and lists larger than ten hosts; lists are capped at fifty.

Wildcard decision: no automatic PSL download or incomplete general suffix heuristic is used. Only the explicitly reviewed `*.gstatic.com` root is supported for now; all unreviewed wildcard roots (including bare/public suffixes) fail closed. Other providers must use exact hostnames. This deliberately trades convenience for avoiding accidental public-suffix-wide permission. Exclusion overlap is rejected during validation and exclusions are rechecked at runtime.

R3 verification on macOS: 174 passed, 0 skipped, 0 failed (56.865 seconds), including the four real-scanner loopback tests.

## R4: per-program constrained CAs

CA CLI commands now require `--program NAME`. Register the program policy first. The CA root contains a private hashed directory for each program, rather than one global signing CA. New CAs contain a critical X.509 NameConstraints extension derived from the intersection of hostname scope and optional asset scope, with hostname/IP exclusions. The listener refuses legacy/unbound CAs, wrong-program CAs and changed constraint sets. Changes require a stopped listener and explicit rotation; existing scope/path checks remain mandatory.

```sh
.venv/bin/python -m expertool --db workbench.db ca-create --program manual-lab
.venv/bin/python -m expertool ca-export-public --program manual-lab --out program-public.pem
.venv/bin/python -m expertool --db workbench.db intercept-start --program manual-lab
# Stop first, update the policy if appropriate, then rotate explicitly:
.venv/bin/python -m expertool --db workbench.db ca-rotate --program manual-lab
.venv/bin/python -m expertool ca-export-public --program manual-lab --out replacement-public.pem
.venv/bin/python -m expertool ca-destroy --program manual-lab
```

Rotation warns to remove the old CA from every browser/OS trust store and manually trust the newly exported public certificate. It returns the new public fingerprint, retains an old **public certificate only** for identification and removes the replaced private key. It refuses while a listener holds the old CA lease. It never silently replaces a CA during creation or changes browser/OS trust. File deletion is not guaranteed secure erasure. Retire old global W1 CAs manually: stop their listeners, remove their trust, and remove their old signing-key files; they are not silently reused or deleted by the per-program flow.

Exact DNS hosts permit only that host and exclude its descendant subtree. Wildcard scope permits descendants and not the apex unless the apex is separately in scope. Some combinations (an exact parent plus selected exact descendants) cannot be expressed precisely as X.509 subtrees: creation refuses them rather than widening the constraint. Split those assessments into separate programs or explicitly review a genuinely authorized subtree scope. IPv4 CIDR/IP SAN constraints are supported, and IP-only leaves have a critical IP SAN and empty subject so numeric common names cannot be misinterpreted as DNS. IPv6 certificate routes remain unsupported. Constraints cannot express HTTP methods, ports or URL paths; those remain enforced per request by the guard.

OpenSSL verification tests deliberately sign a local outside-name leaf, bypassing only the application check in the fixture, and prove chain verification rejects it. Permitted exact/wildcard names verify. This verifies the cryptographic extension with OpenSSL, not every browser or trust-anchor implementation. NameConstraints are defense in depth; validation behavior and trust-anchor treatment can vary. No browser CA trust was installed to test vendor-specific behavior. Continue to treat the signing key as sensitive and delete it when the program ends.

Optional encrypted keys use `ca-create --program NAME --passphrase-env ENV_NAME` (also accepted by `ca-rotate`). The named environment variable must contain at least twelve characters. OpenSSL receives its name through argv and its value through the child environment, never through argv, files, SQLite, logs or reports. Only the environment-variable name is recorded in private CA metadata. Subsequent signing and rotation require the variable; absent/wrong passphrases fail closed. Rotation preserves encryption unless a new passphrase variable is explicitly supplied. Default keys remain unencrypted, owner-only 0600 inside 0700 directories. No passphrase prompt or password storage is added.

W2 history, W3 Repeater, browser trust automation and scanner changes remain outside this repair pass.

R4 verification on macOS: 179 passed, 0 skipped, 0 failed (56.780 seconds), including direct OpenSSL constraint tests and four real-scanner loopback tests. No public target requests or browser trust changes were performed.

## R5: connection reuse decision

The send path and wire framing were reviewed for reuse. Persistent upstream reuse would need to bind a live connection to the freshly resolved address, original TLS identity, current policy revision and response framing on every send; client keep-alive would also need new pipelining/timeout/revocation coverage. That guarantee is not demonstrated by the present tests, so no reuse optimization is added. Client and upstream connections still close after one inspected request. Cached per-host server TLS contexts remain bounded as before. `Accept-Encoding: identity` is unchanged. This is a completed conservative evaluation, not a claim of a new performance improvement.

Final relay-error hardening closes an already-acknowledged blind tunnel instead of injecting a plaintext HTTP error into its bytes. Exact DNS constraint derivation canonicalizes policy hostname spelling before comparison. Tests for third-party passthrough use mocked public DNS/dials routed exclusively to owned local fixtures; no real SSO login or third-party traffic was performed.

Final combined verification on macOS (Darwin), Python 3.14.3: **180 passed, 0 skipped, 0 failed** in 56.932 seconds. All four real-scanner loopback tests were enabled. Python compilation, JavaScript syntax and CA CLI help checks passed. Linux/Windows were not executed; no counts are inferred for them. No installs, sudo, browser/OS trust modification, history/replay features or public target traffic were introduced.
