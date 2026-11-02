# YAML template import and real scanner verification

`template-import` converts compatible Nuclei YAML into the existing pinned JSON subset. Import is offline, does not enable a scanner, and does not establish vulnerability impact. A human reviews the generated template, `review.json`, and manifest before assigning the manifest to a program.

## Optional dependency and command

The scanner runtime remains Python standard library only. YAML import needs PyYAML in the Python environment used for the CLI:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-yaml.txt
.venv/bin/python -m expertool --db scanners.db program-add \
  --name yaml-lab --file examples/scanner-exposure-lab-program.json
.venv/bin/python -m expertool --db scanners.db template-import \
  --program yaml-lab --url http://127.0.0.1:8901/ \
  --file examples/nuclei/exposed-git-config.yaml --out reviewed-templates
```

The supplied `yaml-lab` policy explicitly permits `exposure`/`misconfig` tags and `medium` severity and points to the generated manifest. Review the output, start `python3 examples/lab.py` separately, then run `.venv/bin/python -m expertool --db scanners.db scanner-run --program yaml-lab --tool nuclei --url http://127.0.0.1:8901/` to detect the lab's synthetic `/.git/config`. The lab never contains real repository data. Use an absolute manifest path when launching from another directory. The original scanner-lab policy still permits only `tech`/`info`.

Repeat `--file` for up to 50 templates. The output directory must not already exist. All sources must pass before any bundle is published. Output includes canonical JSON templates, `manifest.json` with SHA256 pins, and `review.json` with source/canonical hashes. Source paths, target credentials and original source content are not included in the review record.

## Admission rules

The importer preserves supported fields. It never silently removes requests, matchers, payloads or other unsupported behavior to make a template pass. Unsupported templates must be rewritten and reviewed separately.

- One UTF-8-compatible YAML document, at most 256 KiB, 20 collection levels, 10,000 parser events.
- SafeLoader with strict string keys; duplicate keys, merge keys, aliases, anchors, explicit tags, timestamps, binary objects and non-JSON values are rejected. Parser errors omit source content.
- Existing safe-subset admission applies: bounded GET/HEAD paths, literal/status matchers, no redirects, raw requests, DSL, extraction, code, payloads, workflows or non-HTTP protocols.
- Current program tool permissions, URL/path scope, tag/severity allowlists and mandatory intrusive exclusions apply at import time and again at scan time.
- Templates and imported matches remain review material/candidates. A GET request can still be sensitive: review each admitted path against program rules.

The importer supports a limited part of [Nuclei's YAML format](https://docs.projectdiscovery.io/templates/structure). Its parser uses [PyYAML SafeLoader](https://pyyaml.org/wiki/PyYAMLDocumentation), with the additional restrictions above. It does not execute or fetch the community template collection.

## Reproducible real-binary tests

Nothing auto-installs during tests. Install trusted vendor tools explicitly first. With macOS isolation available, opt into local tests:

```sh
EXPERTOOL_REAL_SCANNERS=1 \
EXPERTOOL_WPSCAN_DATABASE=/absolute/path/to/trusted/wpscan/db \
.venv/bin/python -m unittest discover -s tests -v
```

These tests use an ephemeral loopback fixture, real binaries, real proxy admission, and verified Seatbelt isolation. The WordPress-shaped fixture checks passive fingerprint parsing; it is not a complete WordPress installation. Missing tools or optional dependencies are reported as skipped. Ordinary test runs leave real-binary tests disabled.

WPScan's trusted offline database must be supplied explicitly through `scanners.wpscan_database`. The bounded copy now includes its required `dynamic_finders.yml`, `LICENSE` and `.last_update`, in addition to JSON/text files. This vendor data is separate from imported Nuclei YAML. No API token or download permission is granted to a scan. WPScan may attempt public WordPress metadata lookups; outside-scope requests remain blocked and the run reports `completed-with-blocks` when the target assessment otherwise succeeds.

## Compatibility fixes verified on this Mac

- httpx 1.12.0: explicit proxy configuration through an inherited anonymous pipe avoids the environment proxy's loopback bypass. Credentials never enter an on-disk config or OS argv.
- Nuclei 3.11.1: pinned templates and anonymous proxy-list pipe work with both fixture matches and a root-only HTTPS smoke check.
- WhatWeb 0.6.4: launcher compensates for the version's proxy-password parsing error in memory. Its pre-proxy DNS lookup uses only pre-authorized IPv4 metadata supplied by the parent, including numeric proxy addresses. Unknown names fail locally. The proxy still resolves, scopes, validates and pins the actual network destination on every admission.
- Ruby adapters honor a supported absolute Ruby shebang or `/usr/bin/env ruby`; opaque wrappers and other shebang forms fail closed.
- WPScan 4.2.0: offline database layout and passive output are verified; exit code 5 means findings, so it is accepted for WPScan only. Other scanner nonzero exits remain failures.

Installation required an explicit user approval. No sudo was used. WPScan's Homebrew formula failed with Apple's Ruby; RubyGems under Homebrew Ruby 3.4 was used instead. WhatWeb was installed from its official source, with an absolute Ruby shebang in the installed copy. No project code invokes package managers or automatic updates.

See [the smoke-test record](scanner-smoke-2026-11-01.md) for observed external and local results. HTTPS remains opaque CONNECT with full-origin scope restrictions; this feature does not add path/method inspection inside encrypted tunnels.
