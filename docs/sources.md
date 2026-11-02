# Research register

Milestone 1 now supersedes earlier external-launch behavior: see [guarded egress](milestone-1-egress.md). Historical Nmap fixture verification does not mean raw Nmap scans are currently enabled through an HTTP-only guard.

Reviewed 2026-11-01. These are references, not vendored dependencies. No upstream payload collections or templates are copied into this project. Catalog descriptions are original summaries. Catalog entries are reference-only, not implemented checks.

| Repository | Intended role | Integration status |
| --- | --- | --- |
| [Galaxy Bugbounty Checklist](https://github.com/0xmaximus/Galaxy-Bugbounty-Checklist) | Topic coverage and hunter workflows | Linked reference |
| [OWASP WSTG](https://github.com/OWASP/wstg) | Testing methodology and coverage taxonomy | Linked reference |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Research reference for vulnerability families | Linked reference |
| [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) | Candidate source of executable detection checks | Not installed or integrated |
| [reconFTW](https://github.com/six2dez/reconftw) | Reference for reconnaissance orchestration | Not installed or integrated |
| [Bug bounty cheatsheet](https://github.com/EdOverflow/bugbounty-cheatsheet) | Supplementary research leads | Linked reference |

Before importing content or shipping an integration, record the exact commit, license, attribution requirements, execution behavior, supported version, and fixture results. Repository descriptions are not evidence of detection accuracy. Never execute code or commands extracted from a research document.

## Planned architecture

1. Catalog: versioned techniques, prerequisites, source provenance, evidence requirements, and custom entries.
2. Program policy: target rules, exclusions, allowed activities, scheduling and request budgets. Current implementation supports hostname-only planning.
3. Tool execution: installed Subfinder can be launched with validated domain arguments, a fixed passive profile, process-group cleanup and runtime/output limits. Target-driven Nmap, guarded curl and local SearchSploit are implemented. WhatWeb/WPScan execution is blocked pending an enforceable egress guard; their parsers remain. External httpx/Nuclei launch remains unimplemented; their saved outputs can be imported. Real provider-backed Subfinder execution has not been verified. Nmap and curl were exercised on the loopback lab; WhatWeb/WPScan/SearchSploit integration used mocked fixtures because those binaries were unavailable.
4. Built-in execution: per-request HTTP scope, destination validation, GET crawling, auth profiles, custom read-only checks, and per-run budgets are implemented. Persistent anonymous schedules use a serial worker and claim leases; budgets are per run, not global across processes.
5. Evidence store: SQLite assets and findings, program separation, deduplication and candidate/confirmed/dismissed states are implemented. Automatic redaction, historical observations and richer asset relationships remain pending.
6. Hunter review: CLI and local browser state changes, finding search/filtering, evidence details, asset observations, scope view and Markdown report export are implemented. Two-account canary validation, built-in/custom condition rechecks, run history and a runs/schedules browser view are implemented. Comprehensive class-specific coverage and arbitrary exploit validation remain pending.

The offline header analyzer implements two posture observations independently of the catalog. Catalog entries remain reference-only. Native saved-output readers support Subfinder hostname text/JSONL, httpx JSONL, and HTTP Nuclei JSONL. These are data adapters, not executable tool integrations. Schema references are documented in the README; fixture tests do not establish compatibility with every released version.

## Coverage semantics

Track reference-only, implemented, fixture-tested, attempted, inconclusive, and confirmed separately. Knowing a technique does not mean the platform can detect it. A completed scan does not establish absence of vulnerabilities.

No claim of exhaustive techniques or 90% vulnerability discovery is made. Establish coverage and false-positive rates with deliberately vulnerable local fixtures before enabling adapters for approved program targets.
