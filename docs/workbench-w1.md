# W1 — opt-in manual interception

W1 adds a separate authenticated loopback proxy for a user-controlled browser. It can inspect HTTP/1.1 requests inside TLS for explicitly permitted hosts, enforce HTTPS path scope on each decrypted request, and forward over verified upstream TLS. It does not add history bodies, HAR, Repeater, account switching, raw capture or automatic testing. W2–W6 have not started. Bulk template work and change detection remain separate work.

## Start with the local lab

These commands use the existing Python standard-library application and an already installed OpenSSL. Nothing installs software or changes trust settings.

```sh
python3 examples/lab.py
```

In another terminal, register the manual-only program and explicitly create the per-install CA once:

```sh
.venv/bin/python -m expertool --db workbench.db program-add --name manual-lab --file examples/interception-lab-program.json
.venv/bin/python -m expertool ca-create
.venv/bin/python -m expertool ca-export-public --out expertool-interception-public.pem
export EXPERTOOL_INTERCEPT_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
.venv/bin/python -m expertool --db workbench.db intercept-start --program manual-lab
```

`ca-create` refuses to replace an existing directory. The default CA directory is `~/.local/share/expertool/interception-ca`. Every CA command and `intercept-start` supports `--ca-dir` for a separate installation/test CA. Only the public certificate is exported. Do not copy or share `ca-key.pem`.

`intercept-start` stays in the foreground and prints a random loopback proxy port and run ID, **not its token**. Set the browser's HTTP and HTTPS proxy to `127.0.0.1` and that printed port. Proxy username is `expertool`; password is the value you put in `EXPERTOOL_INTERCEPT_TOKEN`. The browser may ask for proxy authentication. Use a fresh token for every run. Clear saved browser proxy credentials when finished. Do not paste the token into a program policy, issue, report or command-line argument.

The bundled lab is HTTP-only, so it does not need CA trust. Its program permits only port 8901 and excludes `/never-submit`. Some browsers bypass proxies for localhost: configure the isolated test browser to proxy loopback explicitly. In Firefox, inspect the “No proxy for” list and, if necessary, manually enable `network.proxy.allow_hijacking_localhost` in the test profile. These are browser configuration steps, not actions taken by Expertool.

The browser sends traffic only when you use it, but pages can generate background resource loads and script requests. Expertool cannot prove each browser request represents an individual human click. Keep a dedicated browser profile, narrow program scope, low budgets and state-changing methods disabled until you intend them.

## Manual CA trust and removal

For HTTPS interception, manually trust **the exported public certificate only**, preferably in a dedicated Firefox profile. In Firefox, open Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import, choose the exported public certificate, and select website trust if you intend to use it. For browsers using macOS Keychain, use Keychain Access to import the public certificate into the intended user keychain and configure certificate trust manually. These steps may require OS approval. Expertool never automates Keychain, browser trust, an administrator prompt or sudo.

When finished:

1. Stop interception with Ctrl+C or the authenticated stop command below.
2. Disable the browser proxy and remove saved proxy authentication from the test profile.
3. In Firefox's Authorities list, select “Expertool Local Interception CA” and delete/distrust it. In Keychain Access, remove that certificate from the keychain in which you imported it. Remove trust from every profile/keychain where you added it.
4. If retiring the installation CA, run `ca-destroy`. It refuses while an Expertool listener holds the CA lease. Delete any exported public copies you no longer need.

```sh
.venv/bin/python -m expertool intercept-stop --port PRINTED_PORT
.venv/bin/python -m expertool ca-destroy
```

The stop command uses the same token environment variable and reaches only the local listener; it never sends a target request. It does not need the database argument. Deleting CA files does **not** remove browser or OS trust. File deletion is not guaranteed secure erasure on SSDs or backups. Restarting requires explicit new CA creation if the old CA was destroyed.

## Program permissions and manual methods

Manual interception requires both `allowed_modes: ["manual"]` and `interception.enabled: true`. It is separate from automation permission. A program that bans automated scanners can explicitly permit manual testing; `automation.allowed: false` still blocks those scanners. Scope, URL exclusions, resolved-IP restrictions, ports, required headers, budgets and current policy revision still apply to manual traffic.

GET, HEAD and OPTIONS are permitted by default. To enable POST/PUT/PATCH/DELETE, record a reviewed per-program approval and apply it using `program-update`:

```json
{
  "interception": {
    "enabled": true,
    "state_changing": {
      "enabled": true,
      "approved_by": "YOUR_REVIEWER_LABEL",
      "approved_at": "2026-11-01T12:00:00-06:00"
    }
  }
}
```

Merge this with the actual program policy. Reviewer and timezone-aware approval timestamp are mandatory when enabled. This is a local attestation, not authenticated proof of the reviewer's identity. W1 does not have a per-send confirmation UI; the explicit program flag authorizes browser-originated requests using those methods. Leave it off for passive browsing. GET can also cause state changes on a poorly designed target: method names alone cannot guarantee harmlessness. Existing navigation exclusions still apply, and the scanner proxy retains its GET/HEAD/OPTIONS-only behavior regardless of this flag.

Any policy revision, disabled permission, unreadable policy or expired run budget drops active sessions and invalidates that listener. Restart explicitly after applying a policy change. Already transmitted bytes cannot be recalled, and a state-changing request is never automatically retried. There is no fuzzing/replay loop.

## What is intercepted and verified

The listener binds IPv4 loopback only and requires a per-run authentication token even on its random port. It is distinct from the scanner forward proxy. Linux/Windows interception is refused; existing external-process backends still fail closed there.

For a CONNECT host, the guard first proves the host has at least one permitted HTTPS path, checks all DNS answers and address exclusions, and confirms its port. No certificate is signed for an out-of-scope or excluded host. Narrow HTTPS path scope is supported here because each decrypted HTTP/1.1 request is checked against the full URL afterward; it remains unsupported by the **opaque scanner CONNECT proxy**. A certificate represents host identity, not authorization to access every path on that host.

For every forwarded request, Expertool checks the decrypted method and Host authority, reloads program/scope rules, resolves and validates all returned addresses, pins the actual connection to a validated IPv4 address, reserves shared rate/count/concurrency budget, and checks the policy revision immediately before sending. Browser SNI and Host may not switch to another origin within a tunnel. Upstream TLS uses the original hostname for SNI and certificate verification, the configured trusted roots, and HTTP/1.1 ALPN. Certificate failures return a labeled error and an audit denial; there is no insecure TLS fallback. Certificate-pinned clients and mutual-TLS applications may not work; W1 does not bypass pinning or add client certificate support.

Only HTTP/1.1 is advertised to TLS clients. A client can fall back to HTTP/1.1 when no ALPN protocol is selected; a client that sends an HTTP/2 preface is explicitly refused. HTTP/2 translation is not implemented. HTTP responses close the connection after one request. Chunked request bodies, duplicate headers, Expect/100-continue, nested CONNECT, protocol upgrades and WebSockets are refused. `Alt-Svc` is stripped to avoid advertising an alternate transport through this listener. The browser's own QUIC, direct connections, proxy bypasses or other applications are outside this listener's control; it is not a browser/OS firewall.

Out-of-scope passthrough, WebSocket capture and raw capture are unsupported and refused even if their configuration flags are set true. This conservative W1 decision avoids an unaudited opaque route or plaintext capture while their required controls are absent. No HTTP/2 or WebSocket coverage is claimed.

Request/response buffers share the program's `max_response_bytes` cap. Header lines are capped at 8 KiB, aggregate headers at 32 KiB, and request lines at 8 KiB. Request-line/header parsing has a three-second total deadline; request bodies and upstream operations have bounded timeouts. The run's maximum lifetime and request count also apply. At most 16 clients and 64 TLS host contexts are held per listener. Leaf certificates and keys are created in private temporary directories and removed after loading the TLS context; cached contexts live only for the run.

Unlike the scanner's opaque HTTPS proxy, this listener sees each decrypted HTTP/1.1 request and applies request-level budgets. The scanner proxy is unchanged: it sees host/port only, uses **tunnel admission rate**, and cannot count or inspect HTTP requests inside encrypted tunnels. Its application behavior remains bounded only by pinned templates and fixed tool flags.

## What is stored and where to review it

W1 stores no request/response bodies, URL/query text, cookies, Authorization values, response Set-Cookie values or CA keys in SQLite, reports or application logs. Incoming authentication is registered with the existing redactor; error records use fixed reason codes. Credentials needed to forward the selected request exist temporarily in memory. Public HTTP credentials are refused except on explicitly permitted loopback fixtures. The browser, operating system, crash dumps or manually enabled outside debugging tools have their own storage behavior and are not controlled by W1.

Each forwarded request is recorded under the existing global audit chain with tool `intercept`, host, method, SHA256 of the path **without query**, decision, fixed reason, selected IP, run ID and policy revision. The names of injected user-agent/researcher headers are included, never their values. The Runs & schedules view marks these as “Manual interception audit” and shows injected header names. This is an admission audit, not the full W2 request history or proof that a forwarded operation succeeded.

New events use audit format version 2 so method/path-hash/header-name metadata is covered by the hash. Existing version-1 event hashes and independently retained checkpoints remain valid; historical metadata is not invented or rehashed. `audit-verify` checks both formats. The existing limitations of hash chains and independently retained checkpoints still apply.

## Plain-language threat model

Trusting this CA gives anyone holding its private key the technical ability to impersonate TLS websites to clients that trust it. Program scope is enforced by Expertool's code, **not a cryptographic restriction on the root CA**. A compromised local account, stolen key, malicious dependency or modified application could abuse that trust. The root key is unencrypted and protected by owner-only file permissions (0600) inside a private directory (0700); this does not protect it from malware running as your account. Keep trust confined to the test browser profile, use only authorized programs, stop the listener when finished, and remove trust when retiring the CA.

The relevant boundaries are browser input → local authenticated listener → current scope/method guard → pinned, verified target connection → volatile response buffer. Untrusted target responses do not grant new scope or enable methods. W1 is not a hardened multi-user network service, certificate pinning bypass, OS-wide traffic capture, or encrypted raw-evidence vault. No CA was trusted or installed during implementation; tests use temporary CAs and owned loopback targets only.

## Verification record

All **153 tests passed in 45.970 seconds**, with the four real-scanner loopback tests enabled and no skips. W1 coverage includes CA creation/public export/destruction and permissions, active-CA locking, scoped TLS decryption with a separate trusted upstream CA, untrusted upstream refusal, narrow HTTPS path scope, Host switching, state-changing approval, unchanged automated method limits, HTTP/2 and WebSocket refusal, credential/query non-persistence, active revocation, CLI start/stop, stop-state invalidation, prior audit-checkpoint compatibility, and tamper detection for new metadata. A bounded retry handles short shared-cache policy-reader/write contention without retrying target requests. Python compilation and dashboard JavaScript syntax checks passed. No public target traffic, CA trust installation, tool installation or sudo was used.
