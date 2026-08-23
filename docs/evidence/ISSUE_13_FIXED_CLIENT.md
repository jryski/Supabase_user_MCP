# Issue #13 — bounded M2 credential loader and fixed client seam

## Scope

This slice adds startup-only local credential loading and a single fixed Supabase read seam. It does not register MCP memory tools, perform writes, expose a generic PostgREST client, accept SQL/RPC/relation/path/method/header overrides, or make real network requests.

## Credential boundary

`loadLocalCredentials(startupPath)` accepts only a controller/operator-supplied path. It does not inspect tool arguments, process arguments, CLI token values, or environment variables. The JSON object is closed to exactly:

```json
{
  "projectPublishableKey": "...",
  "userAccessToken": "..."
}
```

The values must be nonblank and distinct. The publishable key must not have JWT shape; the user token must be a three-part JWT with an integer, unexpired `exp` claim. Files that are missing, symlinked, not regular files, larger than 16 KiB, malformed, schema-invalid, expired, or permission-unsafe fail with stable `LocalCredentialError` codes. Errors contain only their code and never echo the path, body, key, token, verifier, or secret fragments.

On POSIX, the default permission check rejects any group/other permission bits. Node does not provide a portable proof of Windows ACL safety. Therefore the default Windows behavior is fail-closed with `CREDENTIAL_PERMISSION_CHECK_UNSUPPORTED`. The trusted controller still needs to integrate a deterministic Windows ACL inspector and pass it through the startup-only `permissionInspector` seam. That inspector must return `insecure` for broad read or write grants and must not put inspected ACL data into errors. This slice does not claim or fake a Windows ACL proof.

## Fixed client boundary

`createFixedSupabaseClient` receives trusted startup configuration, validates an HTTPS origin with no path/query/credentials, and captures credentials in a closure. It exposes only the no-argument `listMemoryRows()` operation with:

- fixed `GET` method;
- fixed `/rest/v1/memories?select=id%2Ccontent&limit=100` path;
- fixed `Accept-Profile: memory` schema profile;
- separate `apikey: <publishable key>` and `Authorization: Bearer <user JWT>` headers;
- a default 5-second timeout, capped at 10 seconds;
- a default 256 KiB response ceiling, capped at 1 MiB, enforced while streaming;
- a JSON array-of-objects response envelope.

The operation accepts no caller input, so callers cannot select or override origin, schema, relation, RPC, method, headers, identity, or token. Failures use secret-free `FixedSupabaseClientError` codes for invalid startup configuration, timeout, network failure, malformed JSON/envelope, non-2xx status, and oversized responses.

## Synthetic TDD evidence

Focused RED was recorded before implementation: both new suites failed to import their then-missing modules. Focused GREEN covers positive reads and paired negative cases, including hostile runtime override attempts and assertions that pin the origin, bearer identity, schema header, abort signal, and response byte ceiling. Every fetch is a Vitest mock; no Supabase lifecycle, Docker, credentials, private data, or network was used.

Final verification commands:

```text
npx vitest run packages/server/src/local-credential-loader.test.ts packages/server/src/fixed-supabase-client.test.ts
npm run check
git diff --check
```

The exact permitted repository paths are checked separately before handoff.
