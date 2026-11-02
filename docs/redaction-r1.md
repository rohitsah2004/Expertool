# R1 — redaction correctness

R1 repairs redaction before request history or replay is built. It changes the existing shared sanitizer only; it does not add capture, network traffic, a new send path, passthrough, constrained CAs, history or Repeater. R2–R5 and W2/W3 have not started.

## Key and parameter handling

Secret keys are compared after camel-case splitting, lowercasing and removal of hyphen, underscore, dot and whitespace separators. Thus `X-API-Key`, `api_key`, `api.key`, `api key` and `apiKey` get equivalent handling. Names containing authorization, cookie, password/passwd, secret, token, API/access key, credential, session, signature, CSRF/XSRF, auth key, private key, JWT or bearer are sensitive. Exact auth, X-Auth, OTP, PIN, SID and sig fields are also sensitive. Matching is intentionally conservative and may mask descriptive metadata whose key contains one of those words.

The small explicit non-sensitive allowlist is `token_type` and `tokenizer`, plus `csrf_required` and `xsrf_required` only when the value is a typed boolean. Their string values still pass through credential/provider-pattern checks. `description` text mentioning the word “token” is not a secret by itself. JSON booleans, nulls and numbers in ordinary fields keep their types.

URL query and form fields additionally redact exact `code`, `sig`, `signature`, `x-amz-signature`, `x-amz-credential`, `x-amz-security-token`, `auth`, `authorization`, `id_token`, `jwt`, `client_secret`, `apikey`, `api_key`, `access_key`, `secret`, `password`, `passwd`, `otp`, `pin`, `session`, `sid` and `key`. Names are decoded before matching, so percent-encoded and repeated secret parameters are covered. These extra parameter rules do not classify every JSON field named `code` as a credential; ordinary application error-code fields remain useful.

OAuth decision: redact `state` when a `code` parameter exists, including an empty code. For URLs this considers both query and parameter-form fragment together; for form bodies it considers that form. Standalone `state` remains visible because it often represents ordinary application state. A program that uses a sensitive standalone state value should supply redacted input or register a qualifying credential; the sanitizer cannot infer every application-specific secret.

Credentials in HTTP(S) URL userinfo are replaced with percent-encoded placeholders. Query/form replacements are URL encoded and preserve host, path, parameter order, duplicates and unrelated fragments. A registered secret occurring in a path is replaced with an encoded marker. More than 2,048 fields makes the parameter component entirely redacted rather than bypassing checks.

## Structured data and headers

`sanitize` recursively masks sensitive object keys and string values. Header dictionaries and ordered header-pair lists keep their shape/case/duplicates while masking sensitive values. An object with `headers` and a string `body` uses its Content-Type to recognize `application/x-www-form-urlencoded`; JSON bodies are parsed recursively. `redact_text(..., content_type="application/x-www-form-urlencoded")` supports explicit standalone form bodies, and ordinary encoded single-line form/query strings are recognized automatically.

`redact_text` and `sanitize_output` parse valid JSON/JSONL before replacing values and serialize it afterward, so replacing a registered credential cannot turn a JSON literal into an unquoted redaction marker. Top-level JSON primitive literals stay valid, too. A numeric string inside JSON remains a string and can be redacted; a numeric JSON literal stays a number unless its key is sensitive. Whitespace/escaping can normalize during JSON serialization. Duplicate JSON keys use the standard library parser's last-value semantics; this is not byte-preserving evidence storage.

Sensitive header/evidence labels mask the whole value, including Cookie/Set-Cookie attributes and authorization schemes. Provider-pattern layers cover JWTs beginning with `eyJ`, AWS access key IDs, GitHub tokens and the existing Stripe/Slack shapes. Bearer values are masked case-insensitively throughout text. These patterns are conservative and can mask a token-looking synthetic string or a benign phrase resembling a Bearer credential.

## Bounded registered-value recall

Credential recall is secondary protection for a previously supplied value later appearing under an unknown key. It stays in process memory only. Registration requires at least 12 characters, at most 4,096 UTF-8 bytes, no control characters, and exclusion of common literals, locale tags and zero-padded small integers. Only sensitive header names are registered. Basic/Bearer scheme prefixes are not registered as part of a credential.

Cookie values are registered only when the cookie name is session/auth/token-like or the value has high entropy (at least 20 characters, 3.5 bits/character, and two character classes). Boolean `true`, `en-US`, short values and ordinary long cookie words therefore cannot contaminate unrelated evidence.

The cache is an LRU: registration and a successful replacement refresh recency. It holds at most 128 values and 64 KiB of value bytes; long values are rejected rather than partially registered. Eviction is expected. Replacement requires token boundaries, including Unicode word characters and hyphens, and occurs inside strings rather than parsed JSON literals. Embedded substrings do not trigger replacement. Cached matching is invalidated on membership changes; syntax/prefix gates avoid needless scans of large benign bodies.

Registered-value matching is **best-effort**. Short, evicted, encoded, transformed or unknown credentials may not match by value. Key/context/pattern redaction is the primary defense. Field names outside these patterns, unsupported encodings, binary data, cryptographic transformations, arbitrary prose secrets and application-specific identifiers can still need human redaction. Existing local files are not rewritten, and this change does not create an encrypted capture store.

## Verification and benchmark

`tests/fixtures/redaction-test.json` has 88 explicitly synthetic shape-in/expected-out cases. They cover the reported header/JSON/query leaks, form fields, OAuth state decisions, percent encoding, duplicates, Cookie/Set-Cookie, nested JSON, JWT/AWS/GitHub/Bearer patterns, URL userinfo, ordered headers, boundary behavior and required false positives. Nine test methods also generate 250 nested JSON documents, test primitive JSONL/literal types, cache entry/byte bounds and LRU eviction, and demonstrate that key-based protection survives credential eviction.

Run the offline benchmark:

```sh
.venv/bin/python scripts/benchmark_redaction.py --iterations 300
```

It reports platform/Python version, byte counts, mean/median/p95 times and whether every measured mean is under 1 ms. Cases are exactly 64 KiB: benign text, structured JSON, and a registered credential near the end, with the 128-entry cache populated. Results are machine/workload dependent, not a worst-case latency guarantee for every arbitrary document. No credentials or request bodies appear in benchmark output, and no network requests are made.

Final R1 verification on macOS (Darwin), Python 3.14.3: **162 passed, 0 skipped, 0 failed** in 49.478 seconds, with all four real-scanner loopback tests enabled. All 153 pre-existing tests remain green. Python compilation passed. The 300-iteration populated-cache benchmark measured mean/median/p95 milliseconds: plain 0.1553/0.1523/0.1747, JSON 0.3092/0.3069/0.3381, registered value 0.7355/0.7284/0.8040. Each measured body was exactly 65,536 bytes. Linux was not executed in this run; no Linux test count is inferred. No public target traffic, installation or browser trust changes occurred.
