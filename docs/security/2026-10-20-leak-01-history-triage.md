# LEAK-01 activation and history triage, 20 October 2026

## Current-head result

The trusted LEAK-01 gate passed on main commit
`bad72b0ab16ff2c256b28dbe8aeee99ed89cce02`:

- [LEAK-01 push run 39425492592](https://github.com/jryski/Supabase_user_MCP/actions/runs/39425492592):
  completed successfully and published the LEAK-01 success status on that commit.
- [CI push run 39425492596](https://github.com/jryski/Supabase_user_MCP/actions/runs/39425492596):
  completed successfully.
- [PR 118](https://github.com/jryski/Supabase_user_MCP/pull/118) merged the existing
  workflow repair from `389e372b363b5f64385bedeb2ee66a185d305d2c`.

This establishes that the configured trusted gate ran successfully on that head.
It does not certify all reachable history or independently certify branch-rule
settings. Scanner policy, credential rules, private-pattern requirements and
failure behavior remain enforced.

## Failure causes and repair

The earlier main run
[38960430527](https://github.com/jryski/Supabase_user_MCP/actions/runs/38960430527)
terminated with `private_patterns_missing_or_oversized`. The required private
pattern configuration was absent. That was an inability result, not a reported
credential exposure.

The same run also logged a separate nonfatal checkout warning: checkout attempted
to update its temporary global Git configuration while
`GIT_CONFIG_GLOBAL=/dev/null` was inherited. PR 118 removes that setting only
during the trusted checkout and restores it in every subsequent policy, install,
fetch and scan step. The bare-fetch subprocess also independently suppresses
ambient Git configuration.

The operator subsequently provisioned the required private-pattern configuration.
Its values are excluded from this receipt, repository files and test fixtures.
No scanner rule or pattern was weakened to obtain the current-head pass.

## Independent local qualification

The exact repair coordinate was independently checked with checksum-verified
Gitleaks 8.30.1 and actionlint 1.7.12:

- The complete `tests/leak/test_gate.sh` suite passed: 81 tests, zero failures,
  zero errors and zero skips.
- Exact-head controls passed against trusted base
  `8aec227f7e91dd7c344595939105dfd2d2dc4916`: a clean synthetic fixture cleared,
  the deliberate synthetic sentinel was blocked, and the exact repair tree
  cleared across 191 paths.
- The checked source diff contains only the existing workflow environment repair.

These results establish the tested coordinate and controls. They are not a claim
that every historical finding is absent.

## Full-history result and triage

The separately requested
[history run 39425206607](https://github.com/jryski/Supabase_user_MCP/actions/runs/39425206607)
on `8aec227f7e91dd7c344595939105dfd2d2dc4916` completed its scan and returned
`findings`, exit 1. It was not an incomplete or unavailable scan.

The scan covered 296 commits, 339 paths and 1,119 unique blobs. Its 949 finding
associations reduce to nine distinct matched hashes in seven test and harness
paths. All findings used the built-in `curl-auth-header`,
`generic-api-key` or `jwt` rules. The configured private-literal rules produced
no findings in this run.

Each distinct match was reproduced with the pinned scanner and compared by its
match hash without publishing the match. Source inspection established:

- Malformed authentication fixtures and planted JWT-like redaction sentinels
  account for eight distinct matches. The JWT-like fixtures have an absent
  algorithm or invalid encoded content, or signature lengths incompatible with
  their declared HS256 or ES256 algorithms.
- One match is a fixed test-case label inside a machine-readable laboratory
  receipt format, not a credential.

No usable credential was identified among these nine matches. This is a
finding-specific triage conclusion, not a general security certification.
Some older branch tips retain the synthetic fixtures even though the current
main and PR 118 trees cleared.

## Disposition

Retain the historical finding result and this classification. Do not relabel the
history run as clear, rewrite history, delete branches or bypass credential rules
solely to make this receipt green.

Keep current-head enforcement active. When older source branches are refreshed,
construct synthetic sentinels at runtime while preserving their denial and
redaction test behavior, as current main already does for the repaired fixtures.
Do not add credential allowlists or broad test-path exemptions.

The public receipt contains no matched values, private-pattern text or encoded
pattern payload, credential material, private deployment locators or raw scanner
reports.
