# Private-alpha status: September 8, 2026

This is a maintainer-reported summary of controlled synthetic testing of a
separate hosted candidate. It does not expand the supported profile on `main`,
publish a hosted service, or mark M4–M6 complete.

## Release scope

The public baseline remains experimental local stdio, read-only, and
synthetic-only. A separate hosted OAuth candidate has passed bounded integration
and real CLI-client tests. It remains a private alpha, not a public beta,
production release, or independently audited security product.

Default data tools remain `memory_get`, `memory_list_recent`, and
`memory_search`. Writes and production artifact access remain outside this
acceptance scope. This documentation update does not merge candidate source,
create a release tag, or publish a package.

## Verified candidate results

| Check | Bounded result |
| --- | --- |
| Repository validation | Format, lint, build/typecheck passed; 862 tests passed, zero failed, six environment-gated integration tests skipped |
| Supported validation environment | Linux, Node 22.20.0, npm 11.19.0 |
| Hosted SDK | 75 checks passed, including ownership/client isolation, list/search, missing identity/client denial, logout and revocation |
| Live grant expiry | Separate 24-check sequence passed; coverage overlaps other checks and is not an additive unique-test count |
| Actual Cursor CLI | Nine completed memory calls across initial, fresh-process and recovery runs, plus fail-closed discovery after revocation |
| Actual Claude Code CLI | Twelve completed memory calls across initial, fresh-process and recovery runs; revoked authorization produced zero available tools |

Claude Code 2.1.263 was tested on Windows. Successful sessions exposed exactly the
three read tools. Owner reads succeeded, another user's lookup returned
`RESOURCE_UNAVAILABLE`, and list/search returned only the authorized fixture.
After the synthetic upstream grant was revoked, the native client reported
`needs-auth` and had no data tools. Reconsent restored the same bounded reads.
The tool inventory and paired tool-use/result events were checked rather than
relying on the model's summary.

The human completed Claude account sign-in. A controller completed the synthetic
MCP login/consent HTTP forms using an existing protected test credential and the
native Claude PKCE callback. This does not establish manual consent-interface
usability. Runtime credentials were not provided to the model.

The later regression source archive has SHA256:

```text
7BFBD5B0D3AC75A3EB034797F7596966F8BCB4A0FE98E82C0C8D990742D6CF40
```

The Claude run used the previously tested hosted-preparation build. The later
regression copy's substantive changes were explicit type annotations and
documentation; do not describe Claude acceptance as a new full regression of a
rebuilt release artifact. The archive digest identifies a retained local
candidate, not an artifact published by this documentation update.

Detailed receipts are retained privately. This summary is not a downloadable
reproduction bundle or an independent attestation. A publishable candidate must
pair its exact source revision with sanitized reproducible evidence.

## Open interoperability and release work

During Claude reauthorization, its MCP SDK warned that a stored OAuth credential
lacked an issuer stamp and that SEP-2352 isolation was inactive for that read.
The diagnostic mentioned pre-upgrade storage or a provider not round-tripping
the issuer. The cause has not been established. Investigate discovery,
authorization response and credential persistence before production use; do not
conclude that either the client or broker alone caused it.

Other work still required:

- Clear login/consent labels and requesting-client/scope descriptions.
- Desktop-client and broader-user acceptance; CLI acceptance is not Desktop or
  claude.ai connector acceptance.
- Durable protected broker state, deployment design and longer operation,
  including refresh, expiry and failure behavior.
- Domain-specific identity mapping and table, view, RPC, Storage and direct-API
  authorization tests for each adopting application.
- Independent architecture/security review and remediation before a supported
  production release.

The six repository skips require separate integration fixtures. Linux test
success does not certify Windows environments without symlink privileges.
Neither client run proves long-duration operation or universal client support.

## Application rollout direction

The next planning priority is a business deployment with its own identity,
roles and policy matrix, followed by shared and personal application stores.
No all-project policy rollout has been performed or accepted.

The proposed model intersects verified principal, client, workspace, active
membership, capability and resource visibility. Shared-store administration is
distinct from personal-store ownership. Application deployments must decide their
own sharing, guardianship and grant-management rules.

Review all callable paths, not only table policies: an elevated function or view
can bypass an otherwise correct row boundary. Deployment-specific findings and
operational details remain in the private review process.

Everyday agent sessions should contain only scoped data-plane tools.
Administration belongs in a separately configured maintenance session with
separate authority. A denied data request must not automatically retry through
a privileged connection. Future writes require separate bounded capabilities,
not an unrestricted SQL fallback.

## Interpretation

The evidence supports controlled private-alpha evaluation with synthetic data.
It does not establish enterprise readiness, an independent security audit,
complete prompt-injection protection, or superiority over another integration.

Remote-profile tracking remains under
[issue #60](https://github.com/jryski/Supabase_user_MCP/issues/60).
The [roadmap](../ROADMAP.md) retains its acceptance gates.
