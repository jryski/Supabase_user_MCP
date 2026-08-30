-- M2 synthetic-only memory read path. No production data or deployment authority.

create schema if not exists memory;
revoke all on schema memory from public, anon, authenticated;
grant usage on schema memory to authenticated;

alter table policy_lab.memories
  add column if not exists content text not null default '',
  add column if not exists created_at timestamptz not null default now(),
  add column if not exists provenance_summary text not null default 'synthetic policy-lab fixture',
  add column if not exists tags text[] not null default '{}';

drop policy if exists grant_is_active_context on policy_lab.capability_grants;
create policy grant_is_active_context on policy_lab.capability_grants
  for select to authenticated
  using (
    principal_id = auth.uid()
    and client_id = auth.jwt() -> 'app_metadata' ->> 'client_id'
    and capability in ('memory:search', 'memory:read')
    and state = 'active'
    and valid_until > now()
  );

create or replace function policy_lab.has_active_capability(
  required_capability text,
  required_workspace text
) returns boolean
language sql
stable
security invoker
set search_path = pg_catalog
as $$
  select exists (
    select 1
    from policy_lab.principals p
    join policy_lab.clients c
      on c.client_id = auth.jwt() -> 'app_metadata' ->> 'client_id'
    join policy_lab.memberships m
      on m.principal_id = p.principal_id
     and m.client_id = c.client_id
     and m.workspace_id = required_workspace
    join policy_lab.capability_grants g
      on g.principal_id = p.principal_id
     and g.client_id = c.client_id
     and g.workspace_id = m.workspace_id
     and g.capability = required_capability
    where p.principal_id = auth.uid()
      and p.identity_eligibility = 'verified'
      and c.state = 'active'
      and c.valid_until > now()
      and m.state = 'active'
      and m.valid_until > now()
      and g.state = 'active'
      and g.valid_until > now()
  );
$$;

revoke all on function policy_lab.has_active_capability(text, text) from public, anon;
grant execute on function policy_lab.has_active_capability(text, text) to authenticated;

create or replace function memory.authorized_memory_get_v1(id text)
returns jsonb
language sql
stable
security invoker
set search_path = pg_catalog
as $$
  select jsonb_build_object(
    'record', (
      select jsonb_build_object(
        'id', m.memory_id,
        'title', m.title,
        'content', m.content,
        'createdAt', m.created_at,
        'provenanceSummary', m.provenance_summary
      )
      from policy_lab.memories m
      where m.memory_id = id
        and policy_lab.has_active_capability('memory:read', m.workspace_id)
      limit 1
    )
  );
$$;

create or replace function memory.authorized_memory_list_recent_v1(
  filters jsonb default null,
  "limit" integer default 25,
  cursor text default null
) returns jsonb
language plpgsql
stable
security invoker
set search_path = pg_catalog
as $$
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
    select 1 from jsonb_object_keys(filters) k where k <> 'tags'
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
    select m.*,
      'cur_' || md5(m.memory_id || '|' || m.created_at::text) as cursor_token
    from policy_lab.memories m
    where policy_lab.has_active_capability('memory:read', m.workspace_id)
      and (
        not (coalesce(filters, '{}'::jsonb) ? 'tags')
        or m.tags @> array(select jsonb_array_elements_text(filters -> 'tags'))
      )
  )
  select cursor is null or exists(select 1 from eligible where cursor_token = cursor)
    into anchor_exists;
  if not anchor_exists then
    raise exception 'invalid cursor' using errcode = '22023';
  end if;

  with eligible as (
    select m.*,
      'cur_' || md5(m.memory_id || '|' || m.created_at::text) as cursor_token
    from policy_lab.memories m
    where policy_lab.has_active_capability('memory:read', m.workspace_id)
      and (
        not (coalesce(filters, '{}'::jsonb) ? 'tags')
        or m.tags @> array(select jsonb_array_elements_text(filters -> 'tags'))
      )
  ), anchor as (
    select created_at, memory_id from eligible where cursor_token = cursor
  ), page_plus_one as (
    select * from eligible e
    where cursor is null
       or (e.created_at, e.memory_id) < (select a.created_at, a.memory_id from anchor a)
    order by e.created_at desc, e.memory_id desc
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
    count(*) as returned_count,
    (select count(*) from page_plus_one) > "limit" as has_more,
    (select cursor_token from page order by created_at asc, memory_id asc limit 1) as next_token
    from page
  )
  select jsonb_build_object('rows', rows)
    || case when has_more then jsonb_build_object('nextCursor', next_token) else '{}'::jsonb end
    into output
  from aggregate_page;

  return output;
end;
$$;

create or replace function memory.authorized_memory_search_v1(
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
as $$
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
    select 1 from jsonb_object_keys(filters) k
    where k not in ('tags', 'createdAfter', 'createdBefore')
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
    select m.*,
      case
        when lower(m.title) like '%' || lower(btrim(query)) || '%' then 1.0::numeric
        else 0.75::numeric
      end as rank,
      'cur_' || md5(m.memory_id || '|' || m.created_at::text || '|' || btrim(query)) as cursor_token
    from policy_lab.memories m
    where policy_lab.has_active_capability('memory:read', m.workspace_id)
      and policy_lab.has_active_capability('memory:search', m.workspace_id)
      and (
        lower(m.title) like '%' || lower(btrim(query)) || '%'
        or lower(m.content) like '%' || lower(btrim(query)) || '%'
      )
      and (
        not (coalesce(filters, '{}'::jsonb) ? 'tags')
        or m.tags @> array(select jsonb_array_elements_text(filters -> 'tags'))
      )
      and (
        not (coalesce(filters, '{}'::jsonb) ? 'createdAfter')
        or m.created_at >= (filters ->> 'createdAfter')::timestamptz
      )
      and (
        not (coalesce(filters, '{}'::jsonb) ? 'createdBefore')
        or m.created_at <= (filters ->> 'createdBefore')::timestamptz
      )
  )
  select cursor is null or exists(select 1 from eligible where cursor_token = cursor)
    into anchor_exists;
  if not anchor_exists then
    raise exception 'invalid cursor' using errcode = '22023';
  end if;

  with eligible as (
    select m.*,
      case
        when lower(m.title) like '%' || lower(btrim(query)) || '%' then 1.0::numeric
        else 0.75::numeric
      end as rank,
      'cur_' || md5(m.memory_id || '|' || m.created_at::text || '|' || btrim(query)) as cursor_token
    from policy_lab.memories m
    where policy_lab.has_active_capability('memory:read', m.workspace_id)
      and policy_lab.has_active_capability('memory:search', m.workspace_id)
      and (
        lower(m.title) like '%' || lower(btrim(query)) || '%'
        or lower(m.content) like '%' || lower(btrim(query)) || '%'
      )
      and (
        not (coalesce(filters, '{}'::jsonb) ? 'tags')
        or m.tags @> array(select jsonb_array_elements_text(filters -> 'tags'))
      )
      and (
        not (coalesce(filters, '{}'::jsonb) ? 'createdAfter')
        or m.created_at >= (filters ->> 'createdAfter')::timestamptz
      )
      and (
        not (coalesce(filters, '{}'::jsonb) ? 'createdBefore')
        or m.created_at <= (filters ->> 'createdBefore')::timestamptz
      )
  ), anchor as (
    select rank, created_at, memory_id from eligible where cursor_token = cursor
  ), page_plus_one as (
    select * from eligible e
    where cursor is null
       or (e.rank, e.created_at, e.memory_id) < (select a.rank, a.created_at, a.memory_id from anchor a)
    order by e.rank desc, e.created_at desc, e.memory_id desc
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
    (select cursor_token from page order by rank asc, created_at asc, memory_id asc limit 1) as next_token
    from page
  )
  select jsonb_build_object('rows', rows)
    || case when has_more then jsonb_build_object('nextCursor', next_token) else '{}'::jsonb end
    into output
  from aggregate_page;

  return output;
end;
$$;

revoke all on function memory.authorized_memory_get_v1(text) from public, anon;
revoke all on function memory.authorized_memory_list_recent_v1(jsonb, integer, text) from public, anon;
revoke all on function memory.authorized_memory_search_v1(text, text, jsonb, integer, text) from public, anon;
grant execute on function memory.authorized_memory_get_v1(text) to authenticated;
grant execute on function memory.authorized_memory_list_recent_v1(jsonb, integer, text) to authenticated;
grant execute on function memory.authorized_memory_search_v1(text, text, jsonb, integer, text) to authenticated;
