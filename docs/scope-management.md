# Scope management

Scope is a mandatory execution boundary. The built-in worker checks the requested URL, each discovered link/redirect, and resolved IP exclusions before connecting. Scope does not expand from a technology match, an external tool suggestion, or a SearchSploit result.

## Import a scope for review

```sh
python3 -m expertool scope-import --format hackerone --file examples/scope-hackerone.json --exclusions examples/scope-exclusions.json --out scope-draft.json
```

This reads saved HackerOne structured-scopes and scope-exclusions JSON, writes a new file without overwriting an existing one, and performs no network requests. API pagination is not fetched automatically; a nonempty next-page link creates a blocker. Combine all pages into a complete data array before importing.

The draft preserves instructions, source hashes, URL/host rules and explicit exclusions. It starts with `authorized: false`, `scope_review.complete: false`, and automation disabled. Submission/bounty eligibility is not treated as permission to scan. Unsupported/ambiguous assets and missing separate exclusions produce review blockers.

Review the complete current program rules and exclusions. Translate prose restrictions into enforceable asset and automation rules, resolve every blocker, and enable only the permitted modes/tools/rates. Mark scope review complete and authorization true only when those declarations are accurate, then register the reviewed policy using `program-add`. There is no automatic consent or natural-language policy interpretation.

The source hash records what was imported; it does not prove that the policy is current. Platform synchronization is not implemented. Local `program-update` revisions are reloaded by production request guards, and active connections are revoked on version changes. See the milestone 1 egress guide.

## Bugcrowd and Intigriti

Native API connectors are not implemented yet. Convert a complete authorized export to this explicit normalized schema, as illustrated by `examples/scope-normalized.json`:

```json
{
  "provider": "intigriti",
  "complete": true,
  "instructions": "Full current program instructions for human review",
  "assets": [
    {"identifier": "*.example.com", "in_scope": true},
    {"identifier": "https://api.example.com/private", "in_scope": false}
  ]
}
```

Allowed provider labels are `hackerone`, `bugcrowd`, `intigriti`, and `manual`. They identify provenance; they do not imply a native API response format. Every asset needs a boolean `in_scope`; missing or string-valued flags are rejected.

```sh
python3 -m expertool scope-import --format normalized --file examples/scope-normalized.json --out normalized-draft.json
```

## Rule semantics

- Hostnames are exact. `*.example.com` matches subdomains, not the apex.
- IPv4 CIDRs are supported. CIDR permissions apply to literal-IP targets; DNS targets still need their own host/URL permission.
- HTTP(S) URL rules preserve scheme, port and path. `https://example.com/` covers that HTTPS origin on port 443. `https://example.com/app` includes only that exact path. Append `/*` to include the path and descendants.
- URL exclusions cover the specified path and descendants. Explicit host/IP/CIDR exclusions take precedence, including excluded IPs resolved by an otherwise permitted hostname.
- Arbitrary wildcard patterns, query/fragment-specific URL rules, ambiguous encoded paths and IPv6 rules are rejected. An unsupported imported asset is a blocker, never silently widened.
- `include`/`exclude` hostname envelopes and `asset_scope` URL rules must both permit a request. Live scan port/path budgets are additional restrictions.
- Offline imports obey URL asset rules too. DNS discovery records can inventory a host without granting permission to request every path on it.

## Automation and identification

```json
{
  "automation": {"allowed": true, "tools": ["http", "curl", "searchsploit"]},
  "scan": {
    "user_agent": "Researcher-Assessment/1.0",
    "request_headers": {"X-Researcher": "your-program-required-identifier"}
  }
}
```

`http` controls the built-in worker, including crawling, custom checks, account-boundary checks, rechecks and schedules. `allowed: false` blocks execution before networking. Tool allowlists also control Subfinder and proactive stages. Legacy manually registered policies retain their previously declared active/passive authorization when no new automation object is present; imported policies always start disabled.

Required user-agent and non-secret identification headers are applied to built-in HTTP and curl. Transport headers, cookie/authorization/API-key headers, duplicate names and CR/LF values are rejected. Credentials belong in origin-bound environment-backed auth profiles. Identification headers are stored with the policy; do not put secrets there. Nmap service probing is blocked when required HTTP identification headers are configured because it cannot attach them consistently.

## External tools and hard scope

WhatWeb and WPScan execution is now blocked unconditionally. Their previous `external_http` opt-in no longer permits launch. The parsers remain for future guarded integrations, but a subprocess that owns its networking cannot currently satisfy per-request scope enforcement. A real intercepting egress boundary is required before re-enabling them.

curl remains usable with pinned resolution, no redirects and required identification headers. Nmap network execution is now skipped because raw scans cannot use the mandatory HTTP egress proxy. Passive Subfinder queries its own data providers when that tool/mode is permitted; returned assets are filtered before storage. Local SearchSploit searches do not grant permission to test any referenced target or run exploit code.

## Source reference

The HackerOne reader follows the documented [structured scopes and scope exclusions](https://api.hackerone.com/hacker-resources/) shapes. Scope-exclusion prose is preserved for review rather than executed or guessed into rules.
