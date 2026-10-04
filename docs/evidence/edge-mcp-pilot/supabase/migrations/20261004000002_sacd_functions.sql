-- SACD minimal first proof, part 2: claim helper, guard, capability function, token hook,
-- PUBLIC execute revocation and ownership. Local synthetic pilot stack only.
begin;

-- Subject from the request claims, or null. Invoker; used by the fixture RLS policy.
create function mcp_cap.claims_sub()
returns uuid
language plpgsql
stable
security invoker
set search_path = ''
as $$
declare
  v text := nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub';
begin
  if v is null or v !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
    return null;
  end if;
  return v::uuid;
end;
$$;

-- SACD-9: rows visible to the owner role only for the validated principal.
create policy fixture_own_rows on mcp_cap.fixture
  for select to mcp_capability_owner
  using (owner_sub = mcp_cap.claims_sub());

-- Session liveness oracle. On Supabase the migration role (postgres) can read auth.sessions but
-- holds USAGE on schema auth without grant option, so the restricted owner role cannot be given
-- direct access. This narrow definer runs one fixed query and returns only a status word; it is
-- executable by mcp_capability_owner alone. Its postgres ownership is a reviewed exception.
create function mcp_cap.session_status(p_session uuid, p_sub uuid, p_client text)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select case
    when s.id is null then 'not_live'
    when s.user_id is distinct from p_sub then 'user_mismatch'
    when s.oauth_client_id is null or s.oauth_client_id::text is distinct from p_client then 'client_mismatch'
    when s.not_after is not null and s.not_after <= pg_catalog.clock_timestamp() then 'expired'
    when p.timebox is not null and s.created_at + p.timebox <= pg_catalog.clock_timestamp() then 'timebox_expired'
    when p.inactivity_timeout is not null
      and coalesce(s.refreshed_at::timestamptz, s.updated_at, s.created_at) + p.inactivity_timeout
        <= pg_catalog.clock_timestamp() then 'inactive'
    else 'live'
  end
  from (select 1) one
  left join auth.sessions s on s.id = p_session
  left join mcp_cap.session_policy p on p.singleton
$$;

-- SACD-11 backend guard. Definer owned by mcp_capability_owner (ownership set below).
create function mcp_cap.sacd_guard()
returns uuid
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  claims jsonb;
  v_aud jsonb;
  v_aud_text text;
  v_exp numeric;
  v_sub uuid;
  v_client text;
  v_session uuid;
  v_status text;
begin
  begin
    claims := nullif(current_setting('request.jwt.claims', true), '')::jsonb;
  exception when others then
    claims := null;
  end;
  if claims is null or pg_catalog.jsonb_typeof(claims) <> 'object' then
    raise exception 'sacd_guard:claims_unreadable' using errcode = '42501';
  end if;
  if claims ->> 'iss' is distinct from 'http://127.0.0.1:64321/auth/v1' then
    raise exception 'sacd_guard:issuer_mismatch' using errcode = '42501';
  end if;
  v_aud := claims -> 'aud';
  if pg_catalog.jsonb_typeof(v_aud) = 'string' then
    v_aud_text := v_aud #>> '{}';
  elsif pg_catalog.jsonb_typeof(v_aud) = 'array' and pg_catalog.jsonb_array_length(v_aud) = 1
    and pg_catalog.jsonb_typeof(v_aud -> 0) = 'string' then
    v_aud_text := v_aud ->> 0;
  else
    raise exception 'sacd_guard:audience_not_singleton' using errcode = '42501';
  end if;
  if v_aud_text is distinct from 'http://127.0.0.1:64321/functions/v1/mcp' then
    raise exception 'sacd_guard:audience_mismatch' using errcode = '42501';
  end if;
  if claims ->> 'role' is distinct from 'mcp_ingress' then
    raise exception 'sacd_guard:role_mismatch' using errcode = '42501';
  end if;
  begin
    v_exp := (claims ->> 'exp')::numeric;
  exception when others then
    v_exp := null;
  end;
  if v_exp is null or v_exp <= extract(epoch from pg_catalog.clock_timestamp()) then
    raise exception 'sacd_guard:token_expired' using errcode = '42501';
  end if;
  v_sub := mcp_cap.claims_sub();
  if v_sub is null then
    raise exception 'sacd_guard:subject_unreadable' using errcode = '42501';
  end if;
  v_client := claims ->> 'client_id';
  if v_client is null or v_client = '' then
    raise exception 'sacd_guard:client_id_missing' using errcode = '42501';
  end if;
  -- Current registry, read at call time (SACD-11, CT-20).
  if not exists (
    select 1 from mcp_cap.client_registry r
    where r.client_id = v_client and r.mcp_resource = v_aud_text
  ) then
    raise exception 'sacd_guard:client_not_approved' using errcode = '42501';
  end if;
  begin
    v_session := (claims ->> 'session_id')::uuid;
  exception when others then
    v_session := null;
  end;
  if v_session is null then
    raise exception 'sacd_guard:session_id_invalid' using errcode = '42501';
  end if;
  v_status := mcp_cap.session_status(v_session, v_sub, v_client);
  if v_status is distinct from 'live' then
    raise exception 'sacd_guard:session_%', v_status using errcode = '42501';
  end if;
  return v_sub;
end;
$$;

-- The one capability function. Definer owned by mcp_capability_owner; guard first; fixed query.
create function mcp_api.list_own_v1(max_rows integer default 50, label_prefix text default '')
returns table (id bigint, label text, created_at timestamptz)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_sub uuid;
  v_rows integer := least(greatest(coalesce(max_rows, 1), 1), 100);
  v_prefix text := coalesce(label_prefix, '');
begin
  if octet_length(v_prefix) > 64 then
    raise exception 'list_own_v1:input_too_large' using errcode = '22023';
  end if;
  v_sub := mcp_cap.sacd_guard();
  return query
    select f.id, f.label, f.created_at
    from mcp_cap.fixture f
    where f.owner_sub = v_sub
      and pg_catalog.left(f.label, pg_catalog.length(v_prefix)) = v_prefix
    order by f.id
    limit v_rows;
end;
$$;

-- SACD-2/3/4 Custom Access Token Hook. Invoker; executed by supabase_auth_admin.
create function mcp_cap.custom_access_token_hook(event jsonb)
returns jsonb
language plpgsql
stable
security invoker
set search_path = ''
as $$
declare
  claims jsonb := event -> 'claims';
  v_client text := coalesce(event -> 'claims' ->> 'client_id', '');
  v_session uuid;
  v_resource text;
begin
  if claims is null or pg_catalog.jsonb_typeof(claims) <> 'object' then
    return pg_catalog.jsonb_build_object('error',
      pg_catalog.jsonb_build_object('http_code', 400, 'message', 'sacd_hook:claims_unreadable'));
  end if;
  if v_client = '' then
    -- No client_id: a first-party session stays unchanged, but an OAuth-client session that
    -- lost its client_id is refused, never downgraded.
    begin
      v_session := (claims ->> 'session_id')::uuid;
    exception when others then
      v_session := null;
    end;
    if v_session is not null and exists (
      select 1 from auth.sessions ss where ss.id = v_session and ss.oauth_client_id is not null
    ) then
      return pg_catalog.jsonb_build_object('error',
        pg_catalog.jsonb_build_object('http_code', 403, 'message', 'sacd_hook:oauth_session_missing_client'));
    end if;
    return pg_catalog.jsonb_build_object('claims', claims);
  end if;
  select r.mcp_resource into v_resource from mcp_cap.client_registry r where r.client_id = v_client;
  if v_resource is not null then
    claims := pg_catalog.jsonb_set(claims, '{aud}', pg_catalog.to_jsonb(v_resource));
    claims := pg_catalog.jsonb_set(claims, '{role}', pg_catalog.to_jsonb('mcp_ingress'::text));
    return pg_catalog.jsonb_build_object('claims', claims);
  end if;
  if exists (select 1 from mcp_cap.declared_non_mcp_client d where d.client_id = v_client) then
    return pg_catalog.jsonb_build_object('claims', claims);
  end if;
  return pg_catalog.jsonb_build_object('error',
    pg_catalog.jsonb_build_object('http_code', 403, 'message', 'sacd_hook:client_not_approved'));
end;
$$;

-- Execute privileges.
revoke all on function mcp_cap.claims_sub() from public, anon, authenticated, service_role;
revoke all on function mcp_cap.sacd_guard() from public, anon, authenticated, service_role;
revoke all on function mcp_cap.session_status(uuid, uuid, text) from public, anon, authenticated, service_role;
grant execute on function mcp_cap.session_status(uuid, uuid, text) to mcp_capability_owner;
revoke all on function mcp_api.list_own_v1(integer, text) from public, anon, authenticated, service_role;
revoke all on function mcp_cap.custom_access_token_hook(jsonb) from public, anon, authenticated, service_role;
grant execute on function mcp_cap.claims_sub() to mcp_capability_owner;
grant execute on function mcp_api.list_own_v1(integer, text) to mcp_ingress;
grant execute on function mcp_cap.custom_access_token_hook(jsonb) to supabase_auth_admin;

-- SACD-7: no PUBLIC execute on functions in exposed schemas, now or by default.
do $revoke$
declare
  fn record;
begin
  for fn in
    select p.oid::regprocedure as sig
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    where n.nspname in ('public', 'graphql_public', 'mcp_api')
  loop
    execute format('revoke execute on function %s from public', fn.sig);
  end loop;
end;
$revoke$;
alter default privileges for role postgres in schema public, graphql_public, mcp_api
  revoke execute on functions from public;

-- SACD-8 ownership: the definer functions belong to the restricted owner role. The migration
-- role may set that role only for the duration of this transfer.
grant create on schema mcp_cap, mcp_api to mcp_capability_owner;
grant mcp_capability_owner to postgres with inherit false, set true;
alter function mcp_cap.sacd_guard() owner to mcp_capability_owner;
alter function mcp_api.list_own_v1(integer, text) owner to mcp_capability_owner;
revoke mcp_capability_owner from postgres;
revoke create on schema mcp_cap, mcp_api from mcp_capability_owner;

-- SACD-10: statement and lock timeouts for the capability role.
alter role mcp_ingress set statement_timeout = '2s';
alter role mcp_ingress set lock_timeout = '1s';

commit;
