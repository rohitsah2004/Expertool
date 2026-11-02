# Milestone 2 — live guarded scanners

Live adapters for ProjectDiscovery httpx, Nuclei, WhatWeb and WPScan are implemented. Each requires an installed trusted executable, explicit program opt-in, active/tool permission, the Milestone 1 proxy and a verified process sandbox. Nothing is installed or updated automatically.

## Enable and run

The bundled `examples/scanner-lab-program.json` opts into the adapters for the loopback lab. Start the fixture separately, register this program once, then run an installed scanner:

```sh
python3 examples/lab.py
```

In another terminal:

```sh
python3 -m expertool --db scanners.db program-add --name scanner-lab --file examples/scanner-lab-program.json
python3 -m expertool --db scanners.db tools
python3 -m expertool --db scanners.db scanner-run --program scanner-lab --tool httpx --url http://127.0.0.1:8901/
python3 -m expertool --db scanners.db scanner-run --program scanner-lab --tool nuclei --url http://127.0.0.1:8901/
python3 -m expertool --db scanners.db serve
```

The generic bundled lab is not a WordPress installation. Use your own authorized local WordPress instance to exercise real WPScan. The initial milestone used mock CLIs. Follow-up verification now includes installed real binaries; see [real scanner verification and YAML import](template-import.md). Tests do not establish compatibility with arbitrary historical vendor versions.

A program's configuration has two controls:

```json
{
  "automation": {"allowed": true, "tools": ["http", "httpx", "nuclei", "whatweb", "wpscan"]},
  "scanners": {
    "enabled": ["httpx", "nuclei", "whatweb", "wpscan"],
    "timeout": 60,
    "max_output_bytes": 2097152,
    "nuclei": {
      "manifest": "examples/nuclei/manifest.json",
      "allowed_tags": ["tech", "exposure", "misconfig", "cve"],
      "allowed_severities": ["info", "low", "medium", "high", "critical"],
      "excluded_tags": []
    },
    "wpscan_database": null
  }
}
```

Also declare authorized scope, active mode and scan budgets. `scanners.enabled` defaults to empty. Old `external_http` and `allow_wpscan_api` flags do not grant execution permission. Relative manifest paths resolve from the CLI working directory; use absolute paths for schedules launched elsewhere.

A live scanner returns `completed`, `completed-with-blocks`, `blocked`, `skipped`, `failed` or `cancelled`. Missing executables/runtimes or unsupported OS isolation are skipped. Policy/template refusal is blocked. Malformed output or a scanner crash is failed. No successful result is imported unless at least one guarded target request was observed. A reported out-of-scope URL or unapproved template ID rejects the result batch.

## Adapter profiles

| Adapter | Fixed behavior | Stored output |
| --- | --- | --- |
| httpx | Exact input scheme, one thread, rate/timeout limits, no retries, technology/title/status/SHA256 output, no update check or redirect flags | Scoped assets and selected service metadata/hashes |
| Nuclei | Only pinned reviewed templates, one worker, no retries, no OAST/headless/code/fuzzing, no raw captures or template embedding | Candidate matches with template ID, SHA256, matched URL and run ID |
| WhatWeb | Aggression 1, no redirects, no cookies, one thread, bounded timeouts | Technology/plugin fingerprints |
| WPScan | Passive detection and plugin detection, one thread, throttle, no update, no forced scan, password or user enumeration options | Core/plugin/theme metadata and informational advisory candidates |

Native output imports remain available using `import --format httpx` and `import --format nuclei`. No installed executable is required for saved-result import. Live output is normalized through those same readers.

## Proactive pipeline

Include the desired adapters in `orchestration.tools`, for example `httpx`, `whatweb`, `wpscan`, `nuclei`, then `searchsploit`, and enable them separately under `scanners.enabled`. The built-in worker runs first. WPScan is selected only after a WordPress signal; httpx and WhatWeb can supply that signal. WPScan component/version hints can feed subsequent local SearchSploit research.

Direct `scanner-run --tool wpscan` is an explicit user selection and does not require a prior signal. Proactive runs never forward account auth profiles to these adapters; they remain anonymous. Each scanner has its own run record and egress audit. Scheduled proactive assessments use the same path. Nmap remains skipped because raw network scanning cannot use the HTTP proxy.

## Curated Nuclei templates

There is no execution of the default community collection, remote template download, arbitrary directory, workflow, or executable DSL. A manifest lists local JSON template files and their SHA256 hashes:

```json
{"templates":[{"path":"fixture-marker.json","sha256":"REPLACE_WITH_THE_FILE_SHA256"}]}
```

See `examples/nuclei/manifest.json` and its pinned fixture. JSON is used as a constrained input representation, then a canonical in-memory-validated snapshot is written as JSON-form YAML for Nuclei. Compatible upstream YAML can now be converted offline using [template-import](template-import.md); this remains a constrained subset, not full Nuclei compatibility.

Supported template fields are `id`, `info`, and 1–5 independent `http` blocks. Requests are GET/HEAD, use BaseURL/RootURL paths, and have bounded word/status matchers. Paths must pass scope; query payloads, additional variable interpolation, raw requests, custom headers, payload generators, extractors, DSL, code, headless, network/DNS/file protocols and workflows are rejected. Credential-like template content is rejected. A manifest is limited to 50 templates, each at most 256 KiB. Symlink/path traversal outside its directory and changed pins are rejected.

A template must match an allowed tag and severity. Mandatory denied tags include `dos`, `fuzz`, `fuzzing`, `bruteforce`, `brute-force`, `intrusive`, `headless`, `code`, and `oast`; extra exclusions can be added, but clearing the list does not remove mandatory exclusions. If any template violates review/policy, the batch is blocked rather than silently widened. The reported template ID and severity must match the approved manifest. Matches remain candidates; pinning does not prove vulnerability impact.

## Credentials and isolated configuration

All adapters start with private HOME/config/cache directories and a reduced environment. Existing scanner config, cloud-upload settings, auth profiles, API tokens and default template paths are not inherited. The scanner's required researcher headers and user agent are supplied explicitly; HTTP proxy injection is still enforced.

- httpx receives explicit proxy configuration through an inherited anonymous pipe (`-config /dev/fd/N`), avoiding environment proxy bypass for loopback targets.
- Nuclei receives its explicit proxy list through an inherited anonymous pipe exposed as `/dev/fd/N`. Proxy credentials are never written to a config file or OS argument list. A vendor version unable to consume this file input fails closed; there is no unsafe fallback.
- A small trusted Ruby launcher reads WhatWeb/WPScan proxy credentials from the environment and passes them to their parsers through Ruby's in-memory ARGV. The OS argument list contains no proxy password. Ruby CLI scripts and an installed compatible Ruby runtime are required; opaque binary/shell wrappers are blocked.

No user account credentials are supplied to these anonymous scanners. WPScan API tokens are not forwarded, and outside-scope API calls cannot bypass the proxy. Optional `wpscan_database` copies trusted local JSON/text data and required vendor database metadata/YAML, at most 50 MiB, into the isolated cache; it does not install/update a database. Without applicable vulnerability data, fingerprint completion is not vulnerability-database coverage. Check WPScan licensing before commercial distribution/SaaS use.

## Preserved safety boundaries

The proxy and sandbox are mandatory. Linux/Windows still refuse external launch without a verified backend. Direct sockets, UDP and spawned-child bypasses remain OS-denied on the supported macOS backend. HTTP methods remain GET/HEAD/OPTIONS at the proxy; an external tool attempting POST or another method receives a denial, even if it considers that action passive.

HTTPS retains the Milestone 1 full-origin CONNECT restrictions. No TLS interception is added; the proxy cannot inspect paths, methods, headers, request counts or HTTP/2 traffic inside encrypted tunnels. Required identification flags are set by the trusted builders. TLS behavior inside a scanner is controlled by that vendor, and these adapters are anonymous; the built-in verified-TLS worker is unchanged. Narrow HTTPS path scope is still blocked instead of bypassed.

Any policy revision invalidates a running scanner session permanently; review and restart are required. Removed permissions cannot be regained by opening another connection inside the old session. Output is rechecked against the current policy before storage. New runs, results and evidence are centrally redacted; JSON/JSONL redaction now preserves valid framing before normalization. No raw captures, stderr, proxy credentials or extracted secret values are stored as evidence.

## Verification and remaining work

Tests cover all four mocked CLIs using real guarded requests, curated pins/tags/severities, unsafe template rejection, candidate-only output, missing/disabled/failed states, policy revocation, rejected out-of-scope/template output, memory-only proxy credentials, inherited-token removal and saved-format compatibility. The complete Milestone 1 and earlier suites remain in regression coverage.

Milestone 3 change detection/notifications has not started. Full upstream template support, account-authenticated external scanning, cross-platform process backends and service-specific API permissions are not added by this milestone.

Upstream flag references: [httpx](https://github.com/projectdiscovery/httpx/blob/main/runner/options.go), [Nuclei](https://github.com/projectdiscovery/nuclei/blob/main/cmd/nuclei/main.go), [WhatWeb](https://github.com/urbanadventurer/WhatWeb), [WPScan](https://github.com/wpscanteam/wpscan).

See [Phase A hardening](phase-a-hardening.md) for version provenance and data-age reporting. Over HTTPS, rate settings enforce tunnel admission rate; the proxy sees only host/port. Request behavior inside tunnels is bounded only by pinned templates and fixed tool flags.
