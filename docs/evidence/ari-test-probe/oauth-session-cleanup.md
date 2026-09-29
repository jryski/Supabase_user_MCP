# Reviewed cleanup: synthetic OAuth session

Controller runbook only. Not executed from this branch. Not acceptance.
This is fixture cleanup of one session row. It is not a revocation receipt
and it does not prove that a presented JWT is rejected.

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
