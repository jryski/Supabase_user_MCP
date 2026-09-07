# User MCP status

Updated September 7, 2026.

PR 65 is merged at `ee6e948bc85a7f347fd6d0e540323d99ab14c5cb`. No `v0.1.0-alpha.1` tag or release was created. PR 64 remains experimental; its old-base review is not current acceptance, and blocking findings are not cleared by unrelated merges.

Subsequent local work added an opt-in maintained-SDK driver: discovery, PKCE, browser consent handoff, strict callback validation and a schema-checked synthetic memory read. Both TypeScript checks and 134 offline tests passed, including 29 driver tests and the prior 105-test suite. These are controller-local, uncommitted results, not claims about this documentation branch or main.

Remaining gates: reconcile the isolated backend with the application's exact issuer/callback and memory RPC contract; exercise the native browser opener, real login/consent, two-identity isolation and revocation. A mock exchange or passing fixture suite is not live acceptance.

No deployment, merge, release or production authorization is implied. Household OS is a consumer of bounded access, not a reason to weaken the access contract.
