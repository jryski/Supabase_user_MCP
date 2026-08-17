# Security Policy

Supabase User MCP is security-sensitive infrastructure. Responsible reports are welcome,
including reports about documentation or proposed designs that could produce unsafe
implementations.

## Supported versions

No production version is currently supported. The repository is in design and
prototyping; all code and documentation should be treated as pre-release.

| Version | Supported |
| --- | --- |
| `main` / pre-release | Best effort |
| Production deployments | None |

## Report a vulnerability privately

Do not open a public issue containing exploit details.

Use [GitHub Private Vulnerability Reporting](https://github.com/jryski/Supabase_user_MCP/security/advisories/new).
If private reporting is unavailable, contact the maintainer through the
[GitHub profile](https://github.com/jryski) without posting sensitive details publicly.

Include, where possible:

- affected commit or version;
- preconditions and trust boundary;
- minimal reproduction steps;
- demonstrated and potential impact;
- whether tokens, secrets, or personal data were exposed; and
- a proposed mitigation, if known.

Never include live credentials or production personal data. Use synthetic records and
redacted logs.

## Response targets

These are goals rather than contractual service levels:

- acknowledgement within 3 business days;
- initial severity assessment within 7 business days;
- coordinated remediation and disclosure timeline after triage.

## Security invariants

A report is especially valuable if it shows that any of these intended invariants can be
broken:

- A request can execute with more authority than its verified principal.
- One tenant, human, agent, or OAuth client can access another's unauthorized records.
- An MCP input can select an arbitrary upstream host, schema, relation, function, or SQL
  statement.
- A caller can mutate canonical data without the required approval state.
- A caller can forge, delete, or rewrite trusted audit events.
- Tokens or sensitive row content appear in logs, errors, traces, or tool metadata.
- Revocation fails beyond its documented bound.
- Untrusted database content expands the caller's authorization envelope.

The complete security design and attacker model are in
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
