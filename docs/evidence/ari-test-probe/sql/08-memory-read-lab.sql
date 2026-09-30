-- TEST-only retained memory-read lab. Not a supabase/migration.
-- This agent does not apply it to hosted Ari TEST, does not open a
-- connection, and does not write credentials.
--
-- Ariadne applies it later, only on project ref odbcejsuuqdzhabjmozi
-- (org pvooiyttujynxquxkqcr, us-east-1), in one batch that already set:
--   select set_config('ari.project_ref', 'odbcejsuuqdzhabjmozi', false);
-- An unset ref, the forbidden ref, or any other ref aborts.
-- Forbidden target: lygftpbjgqgvuunkwnxf and any HOUSE, VAULT, or
-- production project.
--
-- Owned version: ari-memory-read-lab-v1
-- A missing pair of schemas is created. An existing pair must already
-- carry that version and the exact object allowlist. Anything else
-- fails closed. There is no CREATE IF NOT EXISTS.
--
-- Cherry-picked shape only. No access-token hook, no public view, no
-- audit table, no artifact or storage object, no write capability.
-- sql/03 through sql/07 are not modified by this file.
--
-- anon, authenticated, and mcp_ingress must already exist. This file
-- does not create or alter those roles. It revokes the new schemas
-- from PUBLIC, anon, and mcp_ingress. authenticated receives schema
-- USAGE, table SELECT, and EXECUTE on the two helpers and the three
-- read RPCs. policy_lab stays off the Data API. The exposed-schema
-- delta is documented beside this file and is not applied here.

begin;

do $pre$
declare
  project_ref text := current_setting('ari.project_ref', true);
  allowed_ref constant text := 'odbcejsuuqdzhabjmozi';
  forbidden_ref constant text := 'lygftpbjgqgvuunkwnxf';
  version constant text := 'ari-memory-read-lab-v1';
  policy_lab_exists boolean;
  memory_exists boolean;
  policy_comment text;
  memory_comment text;
begin
  if project_ref is not distinct from forbidden_ref
    or coalesce(project_ref, '') = ''
    or project_ref is distinct from allowed_ref
  then
    raise exception
      'refusing memory read lab SQL for project ref %',
      coalesce(project_ref, '<unset>');
  end if;

  if to_regprocedure('auth.uid()') is null
    or to_regprocedure('auth.jwt()') is null
  then
    raise exception 'auth.uid() and auth.jwt() are required';
  end if;

  if not exists (select 1 from pg_roles where rolname = 'anon')
    or not exists (select 1 from pg_roles where rolname = 'authenticated')
    or not exists (select 1 from pg_roles where rolname = 'mcp_ingress')
  then
    raise exception 'anon, authenticated, and mcp_ingress must already exist';
  end if;

  if pg_has_role('mcp_ingress', 'authenticated', 'MEMBER') then
    raise exception 'mcp_ingress must not inherit authenticated';
  end if;

  if exists (
    select 1
    from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'public'
      and relation.relname = 'policy_lab_memory_read'
  ) then
    raise exception 'unexpected public.policy_lab_memory_read';
  end if;

  select exists (select 1 from pg_namespace where nspname = 'policy_lab')
    into policy_lab_exists;
  select exists (select 1 from pg_namespace where nspname = 'memory')
    into memory_exists;

  if policy_lab_exists <> memory_exists then
    raise exception 'partial memory read lab schemas are an unexpected collision';
  end if;

  if not policy_lab_exists then
    perform set_config('ari.memory_read_lab_action', 'create', true);
    return;
  end if;

  select obj_description(namespace.oid, 'pg_namespace')
    into policy_comment
  from pg_namespace as namespace
  where namespace.nspname = 'policy_lab';
  select obj_description(namespace.oid, 'pg_namespace')
    into memory_comment
  from pg_namespace as namespace
  where namespace.nspname = 'memory';

  if policy_comment is distinct from version
    or memory_comment is distinct from version
  then
    raise exception 'existing schemas do not match owned version %', version;
  end if;

  perform set_config('ari.memory_read_lab_action', 'assert', true);
end;
$pre$;

do $create$
begin
  if current_setting('ari.memory_read_lab_action', true) is distinct from 'create' then
    return;
  end if;

  execute $sql$create schema policy_lab$sql$;
  execute $sql$create schema memory$sql$;
  execute $sql$
    revoke all on schema policy_lab from public, anon, authenticated, mcp_ingress
  $sql$;
  execute $sql$
    revoke all on schema memory from public, anon, authenticated, mcp_ingress
  $sql$;
  execute $sql$grant usage on schema policy_lab to authenticated$sql$;
  execute $sql$grant usage on schema memory to authenticated$sql$;
  execute $sql$
    alter default privileges in schema policy_lab
      revoke all on tables from public, anon, authenticated, mcp_ingress
  $sql$;
  execute $sql$
    alter default privileges in schema policy_lab
      revoke all on functions from public, anon, authenticated, mcp_ingress
  $sql$;
  execute $sql$
    alter default privileges in schema policy_lab
      revoke all on sequences from public, anon, authenticated, mcp_ingress
  $sql$;
  execute $sql$
    alter default privileges in schema memory
      revoke all on functions from public, anon, authenticated, mcp_ingress
  $sql$;
  execute $sql$
    create table policy_lab.principals (
      principal_id uuid primary key,
      principal_kind text not null check (
        principal_kind in (
          'human', 'delegated_agent', 'service_agent', 'reviewer', 'system_worker'
        )
      ),
      identity_eligibility text not null check (identity_eligibility in ('verified', 'denied'))
    )
  $sql$;
  execute $sql$
    create table policy_lab.clients (
      client_id text primary key check (
        client_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      ),
      state text not null check (state in ('active', 'expired', 'revoked')),
      valid_until timestamptz not null
    )
  $sql$;
  execute $sql$
    create table policy_lab.memberships (
      principal_id uuid not null references policy_lab.principals,
      client_id text not null references policy_lab.clients,
      workspace_id text not null,
      state text not null check (state in ('active', 'expired', 'revoked')),
      valid_until timestamptz not null,
      primary key (principal_id, client_id, workspace_id)
    )
  $sql$;
  execute $sql$
    create table policy_lab.capability_grants (
      principal_id uuid not null references policy_lab.principals,
      client_id text not null references policy_lab.clients,
      workspace_id text not null,
      capability text not null check (capability in ('memory:search', 'memory:read')),
      state text not null check (state in ('active', 'expired', 'revoked')),
      valid_until timestamptz not null,
      primary key (principal_id, client_id, workspace_id, capability)
    )
  $sql$;
  execute $sql$
    create table policy_lab.memories (
      memory_id text primary key,
      workspace_id text not null,
      title text not null,
      content text not null default '',
      created_at timestamptz not null default now(),
      provenance_summary text not null default 'synthetic policy-lab fixture',
      tags text[] not null default '{}'
    )
  $sql$;
  execute $sql$
    revoke all on all tables in schema policy_lab
      from public, anon, authenticated, mcp_ingress
  $sql$;
  execute $sql$grant select on all tables in schema policy_lab to authenticated$sql$;
  execute $sql$alter table policy_lab.principals enable row level security$sql$;
  execute $sql$alter table policy_lab.principals force row level security$sql$;
  execute $sql$alter table policy_lab.clients enable row level security$sql$;
  execute $sql$alter table policy_lab.clients force row level security$sql$;
  execute $sql$alter table policy_lab.memberships enable row level security$sql$;
  execute $sql$alter table policy_lab.memberships force row level security$sql$;
  execute $sql$alter table policy_lab.capability_grants enable row level security$sql$;
  execute $sql$alter table policy_lab.capability_grants force row level security$sql$;
  execute $sql$alter table policy_lab.memories enable row level security$sql$;
  execute $sql$alter table policy_lab.memories force row level security$sql$;
  execute $sql$
    create function policy_lab.verified_client_id()
    returns text
    language sql
    stable
    security invoker
    set search_path = pg_catalog
    as $fn$
      select coalesce(
        nullif(auth.jwt() ->> 'client_id', ''),
        nullif(auth.jwt() #>> '{app_metadata,client_id}', '')
      );
    $fn$
  $sql$;
  execute $sql$
    revoke all on function policy_lab.verified_client_id()
      from public, anon, mcp_ingress
  $sql$;
  execute $sql$grant execute on function policy_lab.verified_client_id() to authenticated$sql$;
  execute $sql$
    create policy principal_is_verified_subject on policy_lab.principals
      for select to authenticated
      using (principal_id = auth.uid() and identity_eligibility = 'verified')
  $sql$;
  execute $sql$
    create policy client_is_active_claim on policy_lab.clients
      for select to authenticated
      using (
        client_id = policy_lab.verified_client_id()
        and state = 'active'
        and valid_until > now()
      )
  $sql$;
  execute $sql$
    create policy membership_is_active_context on policy_lab.memberships
      for select to authenticated
      using (
        principal_id = auth.uid()
        and client_id = policy_lab.verified_client_id()
        and state = 'active'
        and valid_until > now()
      )
  $sql$;
  execute $sql$
    create policy grant_is_active_context on policy_lab.capability_grants
      for select to authenticated
      using (
        principal_id = auth.uid()
        and client_id = policy_lab.verified_client_id()
        and capability in ('memory:search', 'memory:read')
        and state = 'active'
        and valid_until > now()
      )
  $sql$;
  execute $sql$
    create policy memory_read_intersection on policy_lab.memories
      for select to authenticated
      using (
        exists (
          select 1
          from policy_lab.principals as principal
          join policy_lab.clients as client
            on client.client_id = policy_lab.verified_client_id()
          join policy_lab.memberships as membership
            on membership.principal_id = principal.principal_id
           and membership.client_id = client.client_id
           and membership.workspace_id = memories.workspace_id
          join policy_lab.capability_grants as capability
            on capability.principal_id = principal.principal_id
           and capability.client_id = client.client_id
           and capability.workspace_id = membership.workspace_id
           and capability.capability = 'memory:read'
          where principal.principal_id = auth.uid()
            and principal.identity_eligibility = 'verified'
            and client.state = 'active'
            and client.valid_until > now()
            and membership.state = 'active'
            and membership.valid_until > now()
            and capability.state = 'active'
            and capability.valid_until > now()
        )
      )
  $sql$;
  execute $sql$
    create function policy_lab.has_active_capability(
      required_capability text,
      required_workspace text
    ) returns boolean
    language sql
    stable
    security invoker
    set search_path = pg_catalog
    as $fn$
      select exists (
        select 1
        from policy_lab.principals as principal
        join policy_lab.clients as client
          on client.client_id = policy_lab.verified_client_id()
        join policy_lab.memberships as membership
          on membership.principal_id = principal.principal_id
         and membership.client_id = client.client_id
         and membership.workspace_id = required_workspace
        join policy_lab.capability_grants as capability
          on capability.principal_id = principal.principal_id
         and capability.client_id = client.client_id
         and capability.workspace_id = membership.workspace_id
         and capability.capability = required_capability
        where principal.principal_id = auth.uid()
          and principal.identity_eligibility = 'verified'
          and client.state = 'active'
          and client.valid_until > now()
          and membership.state = 'active'
          and membership.valid_until > now()
          and capability.state = 'active'
          and capability.valid_until > now()
      );
    $fn$
  $sql$;
  execute $sql$
    revoke all on function policy_lab.has_active_capability(text, text)
      from public, anon, mcp_ingress
  $sql$;
  execute $sql$
    grant execute on function policy_lab.has_active_capability(text, text) to authenticated
  $sql$;
  execute $sql$
    create function memory.authorized_memory_get_v1(id text)
    returns jsonb
    language sql
    stable
    security invoker
    set search_path = pg_catalog
    as $fn$
      select jsonb_build_object(
        'record', (
          select jsonb_build_object(
            'id', memory.memory_id,
            'title', memory.title,
            'content', memory.content,
            'createdAt', memory.created_at,
            'provenanceSummary', memory.provenance_summary
          )
          from policy_lab.memories as memory
          where memory.memory_id = id
            and policy_lab.has_active_capability('memory:read', memory.workspace_id)
          limit 1
        )
      );
    $fn$
  $sql$;
  execute $sql$
    create function memory.authorized_memory_list_recent_v1(
      filters jsonb default null,
      "limit" integer default 25,
      cursor text default null
    ) returns jsonb
    language plpgsql
    stable
    security invoker
    set search_path = pg_catalog
    as $fn$
    declare
      output jsonb;
      anchor_exists boolean;
    begin
      if "limit" is null or "limit" < 1 or "limit" > 25 then
        raise exception 'invalid request' using errcode = '22023';
      end if;
      if filters is not null and jsonb_typeof(filters) <> 'object' then
        raise exception 'invalid request' using errcode = '22023';
      end if;
      if filters is not null and exists (
        select 1 from jsonb_object_keys(filters) as key where key <> 'tags'
      ) then
        raise exception 'invalid request' using errcode = '22023';
      end if;
      if filters ? 'tags' and (
        jsonb_typeof(filters -> 'tags') <> 'array'
        or jsonb_array_length(filters -> 'tags') > 5
      ) then
        raise exception 'invalid request' using errcode = '22023';
      end if;

      with eligible as (
        select memory.*,
          'cur_' || md5(memory.memory_id || '|' || memory.created_at::text) as cursor_token
        from policy_lab.memories as memory
        where policy_lab.has_active_capability('memory:read', memory.workspace_id)
          and (
            not (coalesce(filters, '{}'::jsonb) ? 'tags')
            or memory.tags @> array(select jsonb_array_elements_text(filters -> 'tags'))
          )
      )
      select cursor is null or exists (
        select 1 from eligible where cursor_token = cursor
      )
        into anchor_exists;
      if not anchor_exists then
        raise exception 'invalid cursor' using errcode = '22023';
      end if;

      with eligible as (
        select memory.*,
          'cur_' || md5(memory.memory_id || '|' || memory.created_at::text) as cursor_token
        from policy_lab.memories as memory
        where policy_lab.has_active_capability('memory:read', memory.workspace_id)
          and (
            not (coalesce(filters, '{}'::jsonb) ? 'tags')
            or memory.tags @> array(select jsonb_array_elements_text(filters -> 'tags'))
          )
      ), anchor as (
        select created_at, memory_id from eligible where cursor_token = cursor
      ), page_plus_one as (
        select * from eligible as row
        where cursor is null
          or (row.created_at, row.memory_id) < (
            select anchor.created_at, anchor.memory_id from anchor
          )
        order by row.created_at desc, row.memory_id desc
        limit "limit" + 1
      ), page as (
        select * from page_plus_one
        order by created_at desc, memory_id desc
        limit "limit"
      ), aggregate_page as (
        select coalesce(
          jsonb_agg(
            jsonb_build_object(
              'id', memory_id,
              'title', title,
              'content', content,
              'createdAt', created_at,
              'provenanceSummary', provenance_summary
            ) order by created_at desc, memory_id desc
          ), '[]'::jsonb
        ) as rows,
        (select count(*) from page_plus_one) > "limit" as has_more,
        (
          select cursor_token from page
          order by created_at asc, memory_id asc
          limit 1
        ) as next_token
        from page
      )
      select jsonb_build_object('rows', rows)
        || case
          when has_more then jsonb_build_object('nextCursor', next_token)
          else '{}'::jsonb
        end
        into output
      from aggregate_page;

      return output;
    end;
    $fn$
  $sql$;
  execute $sql$
    create function memory.authorized_memory_search_v1(
      query text,
      mode text default 'text',
      filters jsonb default null,
      "limit" integer default 20,
      cursor text default null
    ) returns jsonb
    language plpgsql
    stable
    security invoker
    set search_path = pg_catalog
    as $fn$
    declare
      output jsonb;
      anchor_exists boolean;
    begin
      if query is null or length(btrim(query)) < 1 or length(btrim(query)) > 512 then
        raise exception 'invalid request' using errcode = '22023';
      end if;
      if mode not in ('text', 'semantic') then
        raise exception 'invalid request' using errcode = '22023';
      end if;
      if "limit" is null or "limit" < 1 or "limit" > 20 then
        raise exception 'invalid request' using errcode = '22023';
      end if;
      if filters is not null and jsonb_typeof(filters) <> 'object' then
        raise exception 'invalid request' using errcode = '22023';
      end if;
      if filters is not null and exists (
        select 1
        from jsonb_object_keys(filters) as key
        where key not in ('tags', 'createdAfter', 'createdBefore')
      ) then
        raise exception 'invalid request' using errcode = '22023';
      end if;
      if filters ? 'tags' and (
        jsonb_typeof(filters -> 'tags') <> 'array'
        or jsonb_array_length(filters -> 'tags') > 5
      ) then
        raise exception 'invalid request' using errcode = '22023';
      end if;

      with eligible as (
        select memory.*,
          case
            when lower(memory.title) like '%' || lower(btrim(query)) || '%' then 1.0::numeric
            else 0.75::numeric
          end as rank,
          'cur_' || md5(
            memory.memory_id || '|' || memory.created_at::text || '|' || btrim(query)
          ) as cursor_token
        from policy_lab.memories as memory
        where policy_lab.has_active_capability('memory:read', memory.workspace_id)
          and policy_lab.has_active_capability('memory:search', memory.workspace_id)
          and (
            lower(memory.title) like '%' || lower(btrim(query)) || '%'
            or lower(memory.content) like '%' || lower(btrim(query)) || '%'
          )
          and (
            not (coalesce(filters, '{}'::jsonb) ? 'tags')
            or memory.tags @> array(select jsonb_array_elements_text(filters -> 'tags'))
          )
          and (
            not (coalesce(filters, '{}'::jsonb) ? 'createdAfter')
            or memory.created_at >= (filters ->> 'createdAfter')::timestamptz
          )
          and (
            not (coalesce(filters, '{}'::jsonb) ? 'createdBefore')
            or memory.created_at <= (filters ->> 'createdBefore')::timestamptz
          )
      )
      select cursor is null or exists (
        select 1 from eligible where cursor_token = cursor
      )
        into anchor_exists;
      if not anchor_exists then
        raise exception 'invalid cursor' using errcode = '22023';
      end if;

      with eligible as (
        select memory.*,
          case
            when lower(memory.title) like '%' || lower(btrim(query)) || '%' then 1.0::numeric
            else 0.75::numeric
          end as rank,
          'cur_' || md5(
            memory.memory_id || '|' || memory.created_at::text || '|' || btrim(query)
          ) as cursor_token
        from policy_lab.memories as memory
        where policy_lab.has_active_capability('memory:read', memory.workspace_id)
          and policy_lab.has_active_capability('memory:search', memory.workspace_id)
          and (
            lower(memory.title) like '%' || lower(btrim(query)) || '%'
            or lower(memory.content) like '%' || lower(btrim(query)) || '%'
          )
          and (
            not (coalesce(filters, '{}'::jsonb) ? 'tags')
            or memory.tags @> array(select jsonb_array_elements_text(filters -> 'tags'))
          )
          and (
            not (coalesce(filters, '{}'::jsonb) ? 'createdAfter')
            or memory.created_at >= (filters ->> 'createdAfter')::timestamptz
          )
          and (
            not (coalesce(filters, '{}'::jsonb) ? 'createdBefore')
            or memory.created_at <= (filters ->> 'createdBefore')::timestamptz
          )
      ), anchor as (
        select rank, created_at, memory_id from eligible where cursor_token = cursor
      ), page_plus_one as (
        select * from eligible as row
        where cursor is null
          or (row.rank, row.created_at, row.memory_id) < (
            select anchor.rank, anchor.created_at, anchor.memory_id from anchor
          )
        order by row.rank desc, row.created_at desc, row.memory_id desc
        limit "limit" + 1
      ), page as (
        select * from page_plus_one
        order by rank desc, created_at desc, memory_id desc
        limit "limit"
      ), aggregate_page as (
        select coalesce(
          jsonb_agg(
            jsonb_build_object(
              'id', memory_id,
              'title', title,
              'content', content,
              'createdAt', created_at,
              'provenanceSummary', provenance_summary,
              'rank', rank
            ) order by rank desc, created_at desc, memory_id desc
          ), '[]'::jsonb
        ) as rows,
        (select count(*) from page_plus_one) > "limit" as has_more,
        (
          select cursor_token from page
          order by rank asc, created_at asc, memory_id asc
          limit 1
        ) as next_token
        from page
      )
      select jsonb_build_object('rows', rows)
        || case
          when has_more then jsonb_build_object('nextCursor', next_token)
          else '{}'::jsonb
        end
        into output
      from aggregate_page;

      return output;
    end;
    $fn$
  $sql$;
  execute $sql$
    revoke all on function memory.authorized_memory_get_v1(text)
      from public, anon, mcp_ingress
  $sql$;
  execute $sql$
    revoke all on function memory.authorized_memory_list_recent_v1(jsonb, integer, text)
      from public, anon, mcp_ingress
  $sql$;
  execute $sql$
    revoke all on function memory.authorized_memory_search_v1(text, text, jsonb, integer, text)
      from public, anon, mcp_ingress
  $sql$;
  execute $sql$grant execute on function memory.authorized_memory_get_v1(text) to authenticated$sql$;
  execute $sql$
    grant execute on function memory.authorized_memory_list_recent_v1(jsonb, integer, text)
      to authenticated
  $sql$;
  execute $sql$
    grant execute on function memory.authorized_memory_search_v1(text, text, jsonb, integer, text)
      to authenticated
  $sql$;
  execute $sql$comment on schema policy_lab is 'ari-memory-read-lab-v1'$sql$;
  execute $sql$comment on schema memory is 'ari-memory-read-lab-v1'$sql$;
end;
$create$;

do $assert$
declare
  version constant text := 'ari-memory-read-lab-v1';
  tables text[];
  functions text[];
  policies text[];
  table_name text;
  privilege text;
  role_name text;
  function_name text;
begin
  if current_setting('ari.memory_read_lab_action', true) not in ('create', 'assert') then
    raise exception 'memory read lab action was not set';
  end if;

  if obj_description('policy_lab'::regnamespace, 'pg_namespace') is distinct from version
    or obj_description('memory'::regnamespace, 'pg_namespace') is distinct from version
  then
    raise exception 'owned version comment mismatch';
  end if;

  select coalesce(array_agg(relation.relname order by relation.relname), '{}')
    into tables
  from pg_class as relation
  join pg_namespace as namespace on namespace.oid = relation.relnamespace
  where namespace.nspname = 'policy_lab'
    and relation.relkind = 'r';
  if tables is distinct from array[
    'capability_grants', 'clients', 'memberships', 'memories', 'principals'
  ] then
    raise exception 'policy_lab table allowlist mismatch';
  end if;

  if exists (
    select 1
    from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname in ('policy_lab', 'memory')
      and relation.relkind not in ('r', 'i')
  ) or exists (
    select 1
    from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'memory'
      and relation.relkind = 'r'
  ) then
    raise exception 'unexpected relation in memory read lab schemas';
  end if;

  select coalesce(array_agg(
    namespace.nspname || '.' || procedure.proname || '('
      || pg_get_function_identity_arguments(procedure.oid) || ')'
    order by namespace.nspname, procedure.proname
  ), '{}')
    into functions
  from pg_proc as procedure
  join pg_namespace as namespace on namespace.oid = procedure.pronamespace
  where namespace.nspname in ('policy_lab', 'memory');
  if functions is distinct from array[
    'memory.authorized_memory_get_v1(id text)',
    'memory.authorized_memory_list_recent_v1(filters jsonb, "limit" integer, cursor text)',
    'memory.authorized_memory_search_v1(query text, mode text, filters jsonb, "limit" integer, cursor text)',
    'policy_lab.has_active_capability(required_capability text, required_workspace text)',
    'policy_lab.verified_client_id()'
  ] then
    raise exception 'function allowlist mismatch: %', functions;
  end if;

  if exists (
    select 1
    from pg_proc as procedure
    join pg_namespace as namespace on namespace.oid = procedure.pronamespace
    where namespace.nspname in ('policy_lab', 'memory')
      and (
        procedure.prosecdef
        or not exists (
          select 1
          from unnest(coalesce(procedure.proconfig, array[]::text[])) as config
          where config = 'search_path=pg_catalog'
        )
      )
  ) then
    raise exception 'lab function must be security invoker with search_path pg_catalog';
  end if;

  select coalesce(array_agg(policy.polname order by policy.polname), '{}')
    into policies
  from pg_policy as policy
  join pg_class as relation on relation.oid = policy.polrelid
  join pg_namespace as namespace on namespace.oid = relation.relnamespace
  where namespace.nspname = 'policy_lab';
  if policies is distinct from array[
    'client_is_active_claim',
    'grant_is_active_context',
    'membership_is_active_context',
    'memory_read_intersection',
    'principal_is_verified_subject'
  ] then
    raise exception 'policy allowlist mismatch';
  end if;

  if exists (
    select 1
    from pg_policy as policy
    join pg_class as relation on relation.oid = policy.polrelid
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'policy_lab'
      and (
        policy.polcmd <> 'r'
        or policy.polroles is distinct from array[
          (select oid from pg_roles where rolname = 'authenticated')
        ]
      )
  ) then
    raise exception 'lab policies must be authenticated select only';
  end if;

  if exists (
    select 1
    from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'policy_lab'
      and relation.relkind = 'r'
      and (relation.relrowsecurity is not true or relation.relforcerowsecurity is not true)
  ) then
    raise exception 'policy_lab tables must enable and force row level security';
  end if;

  if exists (
    select 1
    from pg_proc as procedure
    join pg_namespace as namespace on namespace.oid = procedure.pronamespace
    where procedure.proname = 'custom_access_token_hook'
      and namespace.nspname = 'policy_lab'
  ) then
    raise exception 'access-token hook is not part of this lab';
  end if;

  foreach table_name in array array[
    'policy_lab.principals',
    'policy_lab.clients',
    'policy_lab.memberships',
    'policy_lab.capability_grants',
    'policy_lab.memories'
  ]
  loop
    if has_table_privilege('authenticated', table_name, 'SELECT') is not true then
      raise exception 'authenticated select missing on %', table_name;
    end if;
    foreach privilege in array array['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']
    loop
      if has_table_privilege('authenticated', table_name, privilege) then
        raise exception 'authenticated has % on %', privilege, table_name;
      end if;
    end loop;
    foreach role_name in array array['anon', 'mcp_ingress', 'public']
    loop
      foreach privilege in array array['SELECT', 'INSERT', 'UPDATE', 'DELETE']
      loop
        if has_table_privilege(role_name, table_name, privilege) then
          raise exception '% has % on %', role_name, privilege, table_name;
        end if;
      end loop;
    end loop;
  end loop;

  foreach role_name in array array['anon', 'mcp_ingress', 'public']
  loop
    if has_schema_privilege(role_name, 'policy_lab', 'USAGE')
      or has_schema_privilege(role_name, 'memory', 'USAGE')
    then
      raise exception '% can use a lab schema', role_name;
    end if;
  end loop;

  if has_schema_privilege('authenticated', 'policy_lab', 'USAGE') is not true
    or has_schema_privilege('authenticated', 'memory', 'USAGE') is not true
    or has_schema_privilege('authenticated', 'policy_lab', 'CREATE')
    or has_schema_privilege('authenticated', 'memory', 'CREATE')
  then
    raise exception 'authenticated schema privilege mismatch';
  end if;

  foreach function_name in array array[
    'policy_lab.verified_client_id()',
    'policy_lab.has_active_capability(text, text)',
    'memory.authorized_memory_get_v1(text)',
    'memory.authorized_memory_list_recent_v1(jsonb, integer, text)',
    'memory.authorized_memory_search_v1(text, text, jsonb, integer, text)'
  ]
  loop
    if has_function_privilege('authenticated', function_name, 'EXECUTE') is not true then
      raise exception 'authenticated execute missing on %', function_name;
    end if;
    foreach role_name in array array['anon', 'mcp_ingress', 'public']
    loop
      if has_function_privilege(role_name, function_name, 'EXECUTE') then
        raise exception '% can execute %', role_name, function_name;
      end if;
    end loop;
  end loop;
end;
$assert$;

commit;
