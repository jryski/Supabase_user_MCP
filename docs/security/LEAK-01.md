# Repository leak guard

This implements the first post-plan package from the deployment maturity plan.
It scans proposed repository changes for credentials, private literals and raw
artifacts. Activation requires an independently reviewed merge, the protected
pattern secret and a required check configured by the repository owner.

## Trust boundary

The privileged workflow loads its scripts, scanner configuration, policy and
allowlist from the destination branch's reviewed commit. Pull-request files are
Git objects read as data. They are never checked out, imported or executed. No
package installation, project build, Git hook, submodule, LFS download, action
cache or pull-request-controlled executable runs with the pattern secret.

The workflow grants content reads and commit-status writes. Status writes publish
only a fixed context and result to the exact scanned commit, with the run URL.
The private pattern secret is passed only to the trusted scanner step. Scanner
reports contain rule, hashed file identifier, line and match SHA-256. Every file
identifier is hashed because a filename itself can contain a credential.
Raw findings and scanner output remain temporary and are
not uploaded, published in comments or written into this repository.

The bootstrap merge is a human-reviewed installation. The old destination
commit does not yet contain these scripts, so it cannot demonstrate an active
guard on its own installation PR. Required-check activation follows the first
successful default-branch and disposable acceptance runs.

## Scanner and policy

`scripts/leak/scanner-pin.json` pins Gitleaks 8.30.1 for Linux x64. The installer
verifies compressed size and SHA-256 before extracting the single regular-file
executable, then verifies its reported version. It rejects unsupported platforms,
links, traversal, unexpected archive content and checksum/version mismatches.
The configuration extends Gitleaks' built-in rules without a credential bypass.

`LEAK_PRIVATE_PATTERNS` contains strict base64-encoded UTF-8 text with one regular
expression per line. The repository owner provisions it through protected secret
management. It must cover the appropriate names, addresses, project references
and store identifiers. Do not commit the pattern text, its base64 representation
or a real matched value. Missing, empty or invalid patterns fail the scan.

`.leak-policy.json` declares repository privacy and reviewed private-literal path
exemptions. Public repositories have no path exemptions. Private deployment plan
and evidence paths may have explicit exemptions; credentials and raw artifacts
remain forbidden there. The initial private deployment policy names only
`plans/2026-10-supabase-maturity/` as such a path. This allows existing reviewed
technical planning metadata, not personal record exports.

`.leak-allowlist` is a JSON array of separately reviewed, narrow private-literal
exceptions containing rule, exact path, reason, reviewer and UTC expiry date.
The initial array is empty. Invalid or expired entries fail closed. No bypass
label, changed-PR policy, scanner ignore comment or unreviewed pattern is an
authorization to leak data.

## Qualification and activation

1. Review the workflow trust boundary, pin and source diff independently.
2. Run the synthetic acceptance suite with the verified scanner. Seed values
   only inside disposable Git repositories, never in program branches.
3. Merge the installation after review. The repository owner provisions the
   complete `LEAK_PRIVATE_PATTERNS` secret.
4. On disposable branches, prove a credential, private literal and forbidden raw
   artifact each fail, a permitted synthetic literal passes, and missing patterns
   fail closed. Check that proposed scanner/config changes cannot alter the
   trusted scan and that raw findings do not reach logs or artifacts.
5. Run the manual full-history scan once per repository. An incomplete,
   unsupported or unavailable scan is an inability result, not a clean baseline.
   Record only sanitized outcomes privately. Investigate existing findings before
   recording certification.
6. Require the stable `LEAK-01` commit-status context on the default branch.
   Confirm the status is attached to the exact pull-request head GitHub is
   evaluating before relying on it for merges. The base-branch workflow job
   check by itself is not evidence that the proposed head passed.
   Require branches to be up to date, and rescan open heads after private-pattern
   changes. Restrict the accepted workflow source or status publisher so an
   untrusted workflow cannot forge the required context. Where that enforcement
   is unavailable, retain independent human merge review and do not claim a
   tamper-proof automatic merge boundary.
   Test merge-queue behavior separately if the repository uses a merge queue.

The implementation does not claim that repository secrets are provisioned, the
workflow has run on GitHub, branch rules are active or repository histories are
clean. Those require retained repository-specific receipts.

## Coverage and limits

The gate examines selected trees, file names and commit metadata. History mode
also examines fetched refs and reachable annotated-tag metadata. It rejects
shallow and partial repositories, unsupported objects and over-budget inputs rather than
silently skipping them. It does not certify deleted/unreachable Git objects,
external LFS/submodule data, workflow logs, releases, third-party services or
files that were never committed. The scanner's credential rules and the supplied
private patterns determine detection coverage; no scanner proves all possible
private content absent.

In a finding, `commit` identifies the commit containing the content or the
associated Git object for ref/tag metadata. File and virtual metadata identifiers
are always SHA-256 values. A local authorized operator can hash local paths to
locate a finding without publishing the path or its contents.

Rollback reverts the implementation commit. Only the repository owner removes
the required-check setting, with that action recorded in the governing issue.
Do not automatically remove or weaken it to unblock a failing pull request.

## Sources

- Gitleaks 8.30.1. The exact official release archive URL and digest are in
  `scripts/leak/scanner-pin.json`; no scanner binary is committed.
- GitHub Docs, "Securely using pull_request_target":
  [official documentation](https://docs.github.com).
- actions/checkout 7.0.1. Its exact upstream source commit is pinned in
  `.github/workflows/leak-gate.yml`. It retains its upstream license.

The shared leak utility is original implementation code. Each receiving
repository retains its own contribution, independent review and merge rules.
