<h1><img src="partner-threat-feed-logo.svg" width="32" height="32"/>  Partner Threat Feed</h1>

A detection rule library in git from a fictitious threat intelligence partner. It shows a partner delivering
indicator rules for Elastic Security as a git repository instead of a Fleet package, the same way as
[`detection-rules-library`](https://github.com/sdesalas/detection-rules-library). New threat intelligence arrives as
pull requests that add rules, so it is for testing how a large library takes regular updates.

The threat families, campaigns and indicators are made up. The rules install, but they match no real traffic. They
are sample content, not tested for production use.

## Layout

```
manifest.yml                         package manifest (name, version, kibana.version condition)
changelog.yml                        one entry per release
partner-threat-feed-logo.svg         the package icon (the manifest's `icons`)
LICENSE.txt                          Elastic License 2.0 (`source.license: Elastic-2.0`)
rules/
  README.md                          the package description
  <threat type>/<family>/<indicator rule>_<campaign>.json
scripts/
  generate_feed.py                   generates rule files from the feed
```

- The package files are at the root, so the manifest, changelog and license cover everything in the library.
- Every folder under `rules/` holds rule files, and only those. The folder a rule is in says where it belongs.
- One file per rule. Its git history is its list of versions, so don't add a file per version.

## Rule files

Each file holds one rule as `{ attributes, id, type: "security-rule" }`, in JSON, in the same format as the Elastic
prebuilt rules: keys in sorted order, indented by four spaces. `id` is `<rule_id>_<version>`, and
`attributes.rule_id` and `attributes.version` are the source of truth for identity and version, not the file name.

## What the rules detect

Each threat family has a few campaigns, and each campaign has a handful of rules, one per kind of indicator:

| Rule | Type | Matches |
|---|---|---|
| `c2_ip` | query | connections to command and control IP addresses |
| `c2_dns` | query | DNS lookups of command and control domains |
| `file_hash` | query | files written with a known SHA-256 hash |
| `process_hash` | eql | processes started from a binary with a known SHA-256 hash |
| `download_url` | query | web requests to payload URLs |
| `tls_ja3` | query | TLS connections with the implant's JA3 fingerprint |
| `phishing_sender` | query | email from known phishing senders |
| `run_key` | eql | registry run key values the family uses to persist |
| `scheduled_task` | eql | scheduled tasks created with the family's task names |
| `dns_spread` | esql | three or more hosts resolving the same command and control domain |
| `beaconing` | threshold | a host making 20 or more connections to command and control IP addresses |
| `first_contact` | new_terms | the first time a host connects to a command and control domain |

The indicators use reserved ranges: IP addresses are in 198.18.0.0/15, which is reserved for benchmarking, and domains
end in `.example`, `.test` or `.invalid`. Hashes and fingerprints are hashes of made-up strings.

## How the rules are generated

`scripts/generate_feed.py` builds the whole feed as one deterministic stream of rules, family by family, and writes a
slice of it. Release 1.0.0 is the first 12,000 rules. Each feed update is the next 1,000, so updates never overlap
with the release or with each other, and a rule keeps the same id and content however often it is generated.

```sh
python3 scripts/generate_feed.py                                       # dry run of the first 12,000 rules
python3 scripts/generate_feed.py --apply                               # writes them under rules/
python3 scripts/generate_feed.py --start 12000 --count 1000 --apply    # writes feed update 1
```

The script only writes files, it never deletes them. Python 3.9 or newer, standard library only.

## Releases

The `main` branch holds the latest release. Each release is one commit with a tag `main/v<package version>`, for
example `main/v1.0.0`, so a consumer can map a package version to a commit. A consumer can list tags to find
releases, compare the `rules/` trees of two commits to see what changed, and fetch single files without cloning.

Feed updates come as pull requests that only add rule files. They don't change the package version or the
changelog, so they can be merged in any order.

## Using it with Kibana

Nothing in Kibana reads this repo by default. It is used to test delivering rules from a git provider, alongside the
prebuilt rules library.
