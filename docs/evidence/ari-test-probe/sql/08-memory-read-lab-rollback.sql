-- Reviewed recovery for ari-memory-read-lab-v1 only.
-- Not applied by this agent. Ariadne runs it only after a separate review,
-- on project ref odbcejsuuqdzhabjmozi, in a batch that already set
-- ari.project_ref. There is no DROP SCHEMA CASCADE.
--
-- Unknown or new dependencies stop the transaction before any drop.
-- The allowlist is the objects created by sql/08-memory-read-lab.sql.
-- Fixture rows are not a schema rollback. Delete those by exact run id.

begin;

do $pre$
declare
  project_ref text := current_setting('ari.project_ref', true);
  allowed_ref constant text := 'odbcejsuuqdzhabjmozi';
  forbidden_ref constant text := 'lygftpbjgqgvuunkwnxf';
  version constant text := 'ari-memory-read-lab-v1';
  dependent text;
begin
  if project_ref is not distinct from forbidden_ref
    or coalesce(project_ref, '') = ''
    or project_ref is distinct from allowed_ref
  then
    raise exception
      'refusing memory read lab rollback for project ref %',
      coalesce(project_ref, '<unset>');
  end if;

  if to_regnamespace('policy_lab') is null or to_regnamespace('memory') is null then
    raise exception 'STOP memory read lab schemas are absent';
  end if;

  if obj_description('policy_lab'::regnamespace, 'pg_namespace') is distinct from version
    or obj_description('memory'::regnamespace, 'pg_namespace') is distinct from version
  then
    raise exception 'STOP schema version is not %', version;
  end if;

  select string_agg(
    format('%I.%I', namespace.nspname, relation.relname),
    ', ' order by namespace.nspname, relation.relname
  )
    into dependent
  from pg_depend as dependency
  join pg_rewrite as rule on rule.oid = dependency.objid
  join pg_class as relation on relation.oid = rule.ev_class
  join pg_namespace as namespace on namespace.oid = relation.relnamespace
  where dependency.deptype = 'n'
    and dependency.refobjid in (
      select class_oid.oid
      from pg_class as class_oid
      where class_oid.relnamespace in (
        select lab.oid from pg_namespace as lab where lab.nspname in ('policy_lab', 'memory')
      )
    )
    and namespace.nspname not in ('policy_lab', 'memory', 'pg_catalog', 'information_schema');

  if dependent is not null then
    raise exception 'STOP unknown relation dependency %', dependent;
  end if;

  select string_agg(
    format('%I.%I', namespace.nspname, relation.relname),
    ', ' order by namespace.nspname, relation.relname
  )
    into dependent
  from pg_depend as dependency
  join pg_constraint as constraint_row on constraint_row.oid = dependency.objid
  join pg_class as relation on relation.oid = constraint_row.conrelid
  join pg_namespace as namespace on namespace.oid = relation.relnamespace
  where dependency.refobjid in (
      select class_oid.oid
      from pg_class as class_oid
      where class_oid.relnamespace in (
        select lab.oid from pg_namespace as lab where lab.nspname in ('policy_lab', 'memory')
      )
    )
    and namespace.nspname not in ('policy_lab', 'memory', 'pg_catalog', 'information_schema');

  if dependent is not null then
    raise exception 'STOP unknown constraint dependency %', dependent;
  end if;

  select string_agg(
    format('%I.%I', namespace.nspname, procedure.proname),
    ', ' order by namespace.nspname, procedure.proname
  )
    into dependent
  from pg_depend as dependency
  join pg_proc as procedure on procedure.oid = dependency.objid
  join pg_namespace as namespace on namespace.oid = procedure.pronamespace
  where dependency.deptype = 'n'
    and dependency.refobjid in (
      select class_oid.oid
      from pg_class as class_oid
      where class_oid.relnamespace in (
        select lab.oid from pg_namespace as lab where lab.nspname in ('policy_lab', 'memory')
      )
    )
    and namespace.nspname not in ('policy_lab', 'memory', 'pg_catalog');

  if dependent is not null then
    raise exception 'STOP unknown function dependency %', dependent;
  end if;
end;
$pre$;

drop function memory.authorized_memory_search_v1(text, text, jsonb, integer, text);
drop function memory.authorized_memory_list_recent_v1(jsonb, integer, text);
drop function memory.authorized_memory_get_v1(text);
drop policy memory_read_intersection on policy_lab.memories;
drop policy grant_is_active_context on policy_lab.capability_grants;
drop policy membership_is_active_context on policy_lab.memberships;
drop policy client_is_active_claim on policy_lab.clients;
drop policy principal_is_verified_subject on policy_lab.principals;
drop function policy_lab.has_active_capability(text, text);
drop function policy_lab.verified_client_id();
drop table policy_lab.memories;
drop table policy_lab.capability_grants;
drop table policy_lab.memberships;
drop table policy_lab.clients;
drop table policy_lab.principals;
drop schema memory;
drop schema policy_lab;

commit;
