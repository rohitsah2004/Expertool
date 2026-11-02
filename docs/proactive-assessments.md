# Target-driven assessments

**Milestone 2 update:** the opt-in [guarded scanner adapters](milestone-2-scanners.md) supersede the earlier WhatWeb/WPScan execution block. These adapters require `scanners.enabled`, the proxy and process isolation. Nmap remains skipped.

**Milestone 1 override:** all external network execution now requires the verified proxy/process boundary. Nmap network scans are skipped; curl uses the proxy. The profile/parser descriptions below describe retained planning and historical adapters, not permission to bypass this boundary. See [guarded egress](milestone-1-egress.md).

`assess` selects follow-up tools from target evidence. Programs with `orchestration.enabled: true` also route normal single-target `scan` commands and scheduled assessments through this pipeline automatically.

## Flow

1. Run the built-in scoped HTTP inventory and crawler.
2. Fingerprint the target. WordPress resource paths and generator tags supply WordPress signals.
3. Run approved installed tools: Nmap network inventory and guarded curl response probing.
4. Record WordPress-specific follow-up opportunities; WPScan launch is blocked until an enforceable egress guard is available.
5. Search local SearchSploit references using detected products/versions, WordPress and installed component hints. Store references as research leads. Never fetch, copy or execute an exploit.
6. Persist tool results, skipped/unavailable steps and run status for dashboard review.

WhatWeb and WPScan parsers remain available for future guarded integrations; their external processes cannot currently be launched by this pipeline. HTTP failures do not prevent separately authorized Nmap inventory. The pipeline works on one seed at a time; it does not automatically launch tools against newly discovered hosts.

## Local demo

Start the existing loopback fixture in one terminal:

```sh
python3 examples/lab.py
```

Then register this separate proactive program once:

```sh
python3 -m expertool --db proactive.db program-add --name proactive-lab --file examples/proactive-lab-program.json
python3 -m expertool --db proactive.db assess --program proactive-lab --url http://127.0.0.1:8901/ --dry-run
python3 -m expertool --db proactive.db scan --program proactive-lab --url http://127.0.0.1:8901/
python3 -m expertool --db proactive.db serve
```

The lab is a generic web fixture, not a WordPress installation. WordPress follow-up is covered by mocked scanner/response fixtures. The real Nmap and curl adapters were verified against this local lab; actual WhatWeb/WPScan/SearchSploit binaries were unavailable in this environment.

`tools` lists executable availability. Tools are not downloaded or installed automatically. Missing tools produce `unavailable` steps instead of invented results. `completed-with-gaps` means a stage failed, was unavailable, was blocked by policy, or lacked a conditional trigger. A dry run validates configuration and prints the plan without DNS resolution or tool execution.

## Program configuration

Add an `orchestration` object to a program policy before registration. The existing `scan` limits and `active` mode are also required.

```json
{
  "enabled": true,
  "tools": ["nmap", "curl", "whatweb", "wpscan", "searchsploit"],
  "external_http": false,
  "timeout": 90,
  "max_seconds": 300,
  "max_output_bytes": 2097152,
  "nmap_tcp_ports": [80, 443],
  "nmap_udp_ports": [],
  "nmap_os": false,
  "network_authorized_ips": [],
  "allow_wpscan_api": false
}
```

Tool ordering follows the configured list. Put WhatWeb before WPScan and SearchSploit last to use evidence collected earlier in the run. Existing registered policies are create-only; register a new program name/file when changing scope for this version.

### Nmap inventory

Hostname permission alone does not establish that a shared/CDN IP is authorized for host-wide scanning. Nmap requires the resolved address to be explicitly included in `network_authorized_ips`, an array of IP/CIDR ranges authorized for network assessment. This is independent of the HTTP destination port list. Host-level Nmap is skipped for path-restricted web policies.

- TCP uses connect scanning (`-sT`) and light service/version detection (`-sV --version-light`) on configured ports.
- Set `nmap_tcp_ports` to `"all"` to request ports 1–65535, only when permitted. Runtime limits still apply; this does not guarantee completion of every port.
- Set `nmap_os: true` to request `-O`. It is skipped when existing raw-packet privileges are unavailable. OS guesses retain their reported confidence.
- Configure `nmap_udp_ports` with specific allowed UDP ports for a separate `-sU -sV` pass. This also requires existing raw-packet privileges.
- The launcher does not invoke sudo, change privileges, enable NSE scripts, or use `-A`. These profiles do not represent every Nmap scan permutation.

Nmap receives the validated resolved IP and `-n`, not a hostname to resolve again. XML inventory records ports, states, services, products, versions, CPEs and OS matches. Nmap max-rate bounds packet sending; it is not an exact count of HTTP application requests.

### curl

curl uses an explicit resolved address, verified TLS, no inherited proxy, no redirect following, and disabled curlrc loading. Bodies and raw headers are temporary and omitted from stored results. The observed response status is retained.

### WhatWeb and WPScan

Execution is blocked even if `external_http` is true. This legacy field is retained for configuration compatibility, not as a bypass. These engines manage their own requests and cannot yet satisfy mandatory per-request scope enforcement. A future intercepting egress guard must cover their redirects, DNS destinations and request paths before launch is enabled. No claim of WPScan API vulnerability coverage is made by the current pipeline.

### SearchSploit

Only local JSON search is used. Detected product names are tokenized as arguments and never interpreted as shell options/commands. Results retain titles and reference IDs, not local exploit source paths. Version/banner matches can be inaccurate; they are not findings or exploit validation.

## Limits and operational status

Each trusted subprocess has a timeout, combined temporary output cap, and process-group cleanup on exit or failure. The pipeline has a time budget separate from each tool's budget. External engines have their own packet/request accounting; the built-in HTTP request budget is not a global limit across all subprocesses.

One failed tool does not prevent unrelated steps. All stages are visible inside the proactive run's detail JSON in **Runs & schedules**. Scheduled proactive assessments require one seed URL, and their claim lease accounts for the configured pipeline duration. Stop an interactive run with Ctrl+C.

## Upstream references

- [Nmap service detection](https://nmap.org/book/man-version-detection.html) and [OS detection](https://nmap.org/book/man-os-detection.html).
- [WhatWeb usage](https://github.com/urbanadventurer/WhatWeb).
- [WPScan usage and licensing](https://github.com/wpscanteam/wpscan) and [redirect behavior](https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation).
- [SearchSploit manual](https://www.exploit-db.com/searchsploit).

WPScan's license specifies commercial licensing requirements for commercialization, including SaaS. The adapter invokes a separately installed executable; it does not bundle WPScan or establish rights to offer it commercially.
