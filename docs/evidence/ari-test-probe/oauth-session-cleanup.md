# Reviewed cleanup: synthetic OAuth session

Controller runbook only. Not executed from this branch. Not acceptance.
Each delete below is fixture cleanup of one session row. It is not a
revocation receipt and it does not prove that a presented JWT is rejected.
N4 and N5 during `run` use the readback in `lane-b-controller.md`: delete
only the requested session, read target session and refresh counts back to
zero, and leave the opposite session live before typing `continue`.

A Lane B `run` creates three password sessions. Each fresh pair logs in
once and reuses that password session for A and B. The receipt
`sessionLedger` is the cleanup set. A success receipt has three entries,
`positive`, `n4`, and `n5`. Each entry carries `passwordSessionId`,
`sourceSessionId`, and `bSessionId`. A failure receipt carries every pair
ledger accumulated before the abort, plus the safe ids already known for
the pair that aborted. Some of those fields are absent when that pair had
not created them yet. Clean only ids that are present. Do not invent ids.
The top-level `passwordSessionId` is not the whole set. On success it is
the positive pair only. On failure it may be only the pair that aborted.

| | |
| --- | --- |
| Target | `odbcejsuuqdzhabjmozi` only |
| Forbidden | `lygftpbjgqgvuunkwnxf`, HOUSE, VAULT, and any production project |
| Session | `auth.sessions.id` equal to the hook claim `source_session_id` |
| User | `ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid` |

`source_session_id` is the original Auth session id copied by hook v2.
Do not delete by the fresh `session_id` claim. That value is not an
`auth.sessions` row. Do not drop the synthetic user, the marker fixture,
or `mcp_ingress`.

A failed `run` receipt and an `openid-negative` receipt include
`passwordSessionId` when the password-grant access token carried a top-level
`session_id` claim. That value is `auth.sessions.id` for the residual
password session. Use it when `probe.tokenA.source_session_id` is absent.
Do not decode Token A or Token B. Do not paste the access token.

Confirm the dashboard ref before the batch. Stop if it is not the TEST ref.
Replace `<source_session_id>` with `probe.tokenA.source_session_id` from the
redacted probe receipt. That summary also includes `session_id`, `agent_id`,
and `client_id`. Do not decode Token A. Do not paste access tokens, refresh
tokens, or authorization codes into the batch.

## Before

```sql
select session.id, session.user_id, session.not_after, usr.email
from auth.sessions as session
join auth.users as usr on usr.id = session.user_id
where session.id = '<source_session_id>'::uuid;
```

Stop unless that returns exactly one row and the email is
`ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid`.

```sql
select count(*) as refresh_rows
from auth.refresh_tokens
where session_id = '<source_session_id>'::uuid;
```

Record `refresh_rows`. A count of zero is still a valid before-check.

## Delete

One SQL-editor batch, TEST ref only. The refresh-token delete is there so
the session delete is not blocked by that dependency. Scope both statements
to the same session id and the synthetic user.

```sql
delete from auth.refresh_tokens
where session_id = '<source_session_id>'::uuid
  and session_id in (
    select session.id
    from auth.sessions as session
    join auth.users as usr on usr.id = session.user_id
    where session.id = '<source_session_id>'::uuid
      and usr.email = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid'
  );

delete from auth.sessions
where id = '<source_session_id>'::uuid
  and user_id = (
    select id
    from auth.users
    where email = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid'
  );
```

## After

```sql
select count(*) as session_rows
from auth.sessions
where id = '<source_session_id>'::uuid;
```

`session_rows` must be 0.

```sql
select count(*) as user_rows
from auth.users
where email = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid';
```

`user_rows` must still be 1. The user row stays.

## Lane B receipt ledger

After `run`, repeat the before, delete, and after blocks once per UUID on
`sessionLedger`. The nine success-receipt fields are:

| Pair | Password session | A source session | B session |
| --- | --- | --- | --- |
| `positive` | `positive.passwordSessionId` | `positive.sourceSessionId` | `positive.bSessionId` |
| `n4` | `n4.passwordSessionId` | `n4.sourceSessionId` | `n4.bSessionId` |
| `n5` | `n5.passwordSessionId` | `n5.sourceSessionId` | `n5.bSessionId` |

Replace `<session_id>` with that field. Do not paste a token, code, or
verifier. Do not delete the decoy `session_id` claim. Do not delete an id
that is not on the receipt. That preserves the baseline `auth.sessions`
row, the synthetic user, the marker fixture, and `mcp_ingress`.

Two ids may already be gone:

- `n4.sourceSessionId` reads zero when you already typed `continue` for
  `revoke_a_source_session`.
- `n5.bSessionId` reads zero when you already typed `continue` for
  `revoke_b_session`.

A before-count of zero is expected only for those two cases. Run the
delete anyway. It matches nothing. The after readback must still be zero
for both `session_rows` and `refresh_rows`. Then continue with the next
ledger id. If you aborted before that `continue`, the row is still live
and the before-count must be one. A zero on any other ledger id is a stop.
Do not delete a different session to compensate.

Before, for a still-live ledger id:

```sql
select session.id, session.user_id, session.not_after, usr.email
from auth.sessions as session
join auth.users as usr on usr.id = session.user_id
where session.id = '<session_id>'::uuid
  and usr.email = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid';
```

Stop unless that returns exactly one row. For an already-deleted N4 source
or N5 B session, this query returns zero rows. That zero is the expected
before-state. Do not stop the rest of the ledger.

```sql
select count(*) as refresh_rows
from auth.refresh_tokens
where session_id = '<session_id>'::uuid;
```

Record `refresh_rows`. Zero is valid, including the already-deleted N4
source and N5 B session.

Delete, TEST ref only, one ledger id per batch:

```sql
delete from auth.refresh_tokens
where session_id = '<session_id>'::uuid
  and session_id in (
    select session.id
    from auth.sessions as session
    join auth.users as usr on usr.id = session.user_id
    where session.id = '<session_id>'::uuid
      and usr.email = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid'
  );

delete from auth.sessions
where id = '<session_id>'::uuid
  and user_id = (
    select id
    from auth.users
    where email = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid'
  );
```

After each id:

```sql
select count(*) as session_rows
from auth.sessions
where id = '<session_id>'::uuid;
```

```sql
select count(*) as refresh_rows
from auth.refresh_tokens
where session_id = '<session_id>'::uuid;
```

`session_rows` must be 0. `refresh_rows` must be 0. That includes the N4
source and the N5 B session that `run` already deleted.

After every ledger id:

```sql
select count(*) as user_rows
from auth.users
where email = 'ari-probe-synthetic@odbcejsuuqdzhabjmozi.invalid';
```

`user_rows` must still be 1. The user row stays. Do not drop the marker
fixture or `mcp_ingress`. Do not delete `auth.sessions` rows whose ids are
absent from `sessionLedger`.
