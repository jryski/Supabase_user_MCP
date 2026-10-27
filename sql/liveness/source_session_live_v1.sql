-- Source-session liveness check for the native-user read composition.
--
-- Not a migration. Nothing in this repository applies it. Installing it on a
-- project is a separate, operator-approved step, because it adds a function
-- that the authenticated role can call through the Data API.
--
-- Caller: Token B (the downstream Data API credential) through
--   POST /rest/v1/rpc/source_session_live_v1
--   {"source_session_id": "<uuid>", "a_client_id": "<oauth client id>"}
-- The server treats only JSON true as live. Every other result, error, or
-- timeout fails closed.
--
-- Returns true only when all of these hold:
--   1. The caller is authenticated (auth.uid() is not null).
--   2. The caller's own session (session_id claim) still exists for that user
--      and has not reached not_after.
--   3. The named source session exists, belongs to the same user, has not
--      reached not_after, and is a different session from the caller's.
--   4. The source session was issued to the named OAuth client. The client is
--      read through to_jsonb(...) ->> 'oauth_client_id', so the function
--      installs on Auth schemas with or without that column. Where the column
--      is absent or null, the check is false: it fails closed.
--
-- It reads auth.sessions only. It writes nothing and returns no row data.

create or replace function public.source_session_live_v1(
  source_session_id uuid,
  a_client_id text
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(
    (
      select
        auth.uid() is not null
        and a_client_id is not null
        and length(a_client_id) between 1 and 128
        and source.id is distinct from caller.id
        and (to_jsonb(source) ->> 'oauth_client_id') = a_client_id
      from auth.sessions as source
      join auth.sessions as caller
        on caller.user_id = source.user_id
      where source.id = source_session_live_v1.source_session_id
        and source.user_id = auth.uid()
        and (source.not_after is null or source.not_after > now())
        and caller.id = nullif(auth.jwt() ->> 'session_id', '')::uuid
        and (caller.not_after is null or caller.not_after > now())
    ),
    false
  );
$$;

revoke all on function public.source_session_live_v1(uuid, text) from public;
revoke all on function public.source_session_live_v1(uuid, text) from anon;
grant execute on function public.source_session_live_v1(uuid, text) to authenticated;
