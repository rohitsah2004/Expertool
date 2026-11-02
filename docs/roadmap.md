# Bug bounty product roadmap

Milestone 1 guarded egress is implemented; see `milestone-1-egress.md` for verified OS support, strict HTTPS limitations, and the external-tool restrictions that supersede earlier network-launch behavior. Milestone 2 guarded scanner adapters are implemented; see `milestone-2-scanners.md`. Milestone 3 has not started.

The product follows this priority order. Automation discovers candidates; evidence validation and program rules govern follow-up. No item below implies exhaustive vulnerability coverage.

| Priority | Capability | Current implementation | Remaining |
| --- | --- | --- | --- |
| 1 | Mandatory scope management | Exact hosts/wildcards/IPv4 CIDRs, URL scheme/port/path rules, exclusions including resolved IPs, disabled review drafts, HackerOne offline exports, normalized provider exports, automation/tool restrictions | Native Bugcrowd/Intigriti connectors, authenticated sync, live revocation, guarded external HTTP engines |
| 2 | Recon and asset discovery | Passive Subfinder launcher, DNS validation, recurring assessments | Provider adapters, ASN/range discovery, optional wordlist discovery, recurring discovery jobs |
| 3 | Liveness and fingerprints | HTTP status/title/header posture, WordPress hints, pinned curl, approved Nmap service/version/OS/UDP profiles | Rich framework/CDN/WAF/TLS inventory and confidence models |
| 4 | Endpoint discovery | Bounded HTML crawling and form-method inventory | JavaScript parsing, historical URL sources, content wordlists, parameter discovery |
| 5 | Pluggable checks | Custom GET status/header/literal checks, header/cookie observations, Nuclei output import | Guarded template execution, broader class-specific CVE/exposure checks |
| 6 | Change monitoring | Persisted observations, runs and recurring scans | Cross-run asset/endpoint/content diffs and change alerts |
| 7 | Secrets detection | Exact auth-value redaction and omitted raw captures | Secret detectors, public-repository sources, permitted validation and false-positive controls |
| 8 | Politeness controls | Sequential request rate/size/time/depth budgets, configurable identification headers/user agent, tool time/output limits | Shared per-target budgets, concurrency controls, retry/backoff and program-specific windows |
| 9 | Storage and triage | SQLite, deduplication, candidate/confirmed/dismissed states, evidence and validation history, dashboard | Tags, reported status, richer ownership and filtering, optional Postgres |
| 10 | Evidence and notifications | Markdown reports, response hashes, validation evidence, local dashboard | Redacted request/response artifacts, target screenshots, notification adapters |

## Architecture rules

Each stage has structured data inputs/outputs. Import adapters do not run code extracted from sources. Every network stage must demonstrate its scope and rate enforcement before it is enabled. External tool output is evidence to review, not an instruction stream. Checks do not automatically promote their own matches to confirmed vulnerabilities.

Notifications must be configured with an explicit destination and content policy before delivery. No notification has been sent or destination connected. Raw secrets, account cookies and complete responses are not notification payload defaults.
