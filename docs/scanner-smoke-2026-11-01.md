# Real scanner smoke test — November 1, 2026 (America/Chicago)

The user explicitly approved no-sudo installation and designated an owner-controlled domain as the external test target. The target identifier is omitted from this public record. Local fixtures were tested first. The external policy included exactly that HTTPS origin, no subdomains or other hosts, anonymous access, one request per second, 20-second scanner limits and no redirect-following flags. The HTTPS proxy enforces the full-origin CONNECT boundary; it cannot inspect requests inside TLS.

| Scanner | Installed version | Local result | External result |
| --- | --- | --- | --- |
| ProjectDiscovery httpx | 1.12.0 | Completed through proxy; status/title/technology/hash parsed | Completed; one admitted CONNECT |
| Nuclei | 3.11.1 | Completed; marker match and imported YAML Git-config exposure match stored as candidates | Completed; one admitted CONNECT; root reachability condition only |
| WhatWeb | 0.6.4 (official source checkout) | Completed; plugin fingerprints parsed | Completed; one admitted CONNECT; HTTP 200 |
| WPScan | 4.2.0 | Completed-with-blocks on WordPress-shaped fixture; WordPress 6.7 parsed; five target requests allowed | Not run: the external fingerprints showed Vercel/HTML content without a WordPress signal |

No external vulnerability is claimed. The external Nuclei template deliberately identifies a root response condition, with the title “Root reachability (not a vulnerability).” It does not test exploitability. No credentials or password attacks were used. No external endpoint discovery or Git-config exposure template was run on the public target.

The generic local lab is correctly refused by WPScan as non-WordPress. A separate local WordPress-shaped HTTP fixture exercises passive parsing, not complete WordPress coverage. WPScan attempted `api.wordpress.org` metadata lookup; the proxy denied it and the test verified that every allowed destination remained loopback. Fingerprint data was downloaded separately as an explicitly authorized installation step, then copied into isolated scan homes without live updates or API credentials.

Initial incompatible adapter attempts remain recorded as blocked/failed. Fixes were verified with the real binaries: explicit pipe-backed httpx proxy config, WhatWeb's proxy-password correction and approved DNS metadata, supported absolute Ruby interpreter selection, required WPScan database files, and WPScan-specific exit code 5 handling. The proxy and OS isolation were retained throughout.

The follow-up test suite includes optional real-binary loopback tests. See [reproduction instructions](template-import.md). Local external-smoke artifacts are under `reports/real-smoke-2026-11-01/`: `smoke.db`, exact program policy, reviewed root-only template bundle, `final-results.json`, and the stored snapshot. They are ignored by source control. Earlier refused attempts are retained in the SQLite run history. The final results file contains the latest outcome per tested external scanner.

Installed scanner paths are `/opt/homebrew/bin/httpx`, `/opt/homebrew/bin/nuclei`, `/opt/homebrew/bin/whatweb`, and `/opt/homebrew/bin/wpscan`. WhatWeb resolves to the user-owned source installation under `~/.local/share/expertool/WhatWeb`; WPScan resolves to its native RubyGems script. The offline database is `~/.local/share/expertool/wpscan-db`; configure that absolute path explicitly in a program's `scanners.wpscan_database` before use.

Final verification: **109 tests passed in 32.368 seconds**, with real-scanner tests enabled and the offline WPScan database configured. No tests were skipped. CLI YAML-import acceptance and Python compilation also passed. Generated Python fixture shebangs now resolve the interpreter symlink so tests work from the project virtual environment despite spaces in the workspace path.
