-- Reviewed recovery for ari-memory-read-lab-v1 only.
-- Not applied by this agent. Ariadne runs it only after a separate review,
-- on project ref odbcejsuuqdzhabjmozi, in a batch that already set
-- ari.project_ref. There is no DROP SCHEMA CASCADE.
--
-- Unknown or new dependencies stop the transaction before any drop.
-- The owned internal manifest is revalidated before any drop: policy
-- target, command, permissive mode, roles, and expression; function
-- volatility and body; triggers, constraints, columns, and indexes.
-- Quoted literals stay intact. The same authenticated-select ownership
-- check runs before any drop. An unknown or drifted object stops the
-- transaction. There is no CASCADE.
-- The allowlist is the objects created by sql/08-memory-read-lab.sql.
-- Fixture rows are not a schema rollback. Delete those by exact run id.

begin;

create or replace function pg_temp.manifest_text(input text)
returns text
language plpgsql
immutable
as $norm$
declare
  index integer := 1;
  size integer;
  ch text;
  output text := '';
  in_quote boolean := false;
  pending boolean := false;
begin
  if input is null then
    return '';
  end if;
  size := length(input);
  while index <= size loop
    ch := substr(input, index, 1);
    if in_quote then
      output := output || ch;
      if ch = '''' then
        if substr(input, index + 1, 1) = '''' then
          output := output || '''';
          index := index + 1;
        else
          in_quote := false;
        end if;
      end if;
    elsif ch = '''' then
      if pending and output <> '' then
        output := output || ' ';
      end if;
      pending := false;
      in_quote := true;
      output := output || ch;
    elsif ch ~ '[[:space:]]' then
      pending := true;
    else
      if pending and output <> '' then
        output := output || ' ';
      end if;
      pending := false;
      output := output || ch;
    end if;
    index := index + 1;
  end loop;
  return output;
end;
$norm$;

do $pre$
declare
  project_ref text := current_setting('ari.project_ref', true);
  allowed_ref constant text := 'odbcejsuuqdzhabjmozi';
  forbidden_ref constant text := 'lygftpbjgqgvuunkwnxf';
  version constant text := 'ari-memory-read-lab-v1';
  dependent text;
  owned_policy text;
  owned_column text;
  owned_constraint text;
  owned_function text;
  owned_index text;
  owned_trigger integer;
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

  if exists (
    select 1
    from pg_policy as policy
    join pg_class as relation on relation.oid = policy.polrelid
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'policy_lab'
      and (
        policy.polcmd <> 'r'
        or policy.polpermissive is not true
        or policy.polroles is distinct from array[
          (select oid from pg_roles where rolname = 'authenticated')
        ]
      )
  ) then
    raise exception 'STOP owned manifest drift: policy';
  end if;

  select md5(string_agg(
      policy.polname || '@' || relation.relname
      || '|' || policy.polcmd::text
      || '|' || policy.polpermissive::text
      || '|' || case
        when policy.polroles = array[0]::oid[] or cardinality(policy.polroles) = 0 then 'public'
        else (
          select string_agg(role.rolname, ',' order by role.rolname)
          from pg_roles as role
          where role.oid = any (policy.polroles)
        )
      end
      || '|' || pg_temp.manifest_text(pg_get_expr(policy.polqual, policy.polrelid)),
      E'\n' order by policy.polname
    ))
    into owned_policy
  from pg_policy as policy
  join pg_class as relation on relation.oid = policy.polrelid
  join pg_namespace as namespace on namespace.oid = relation.relnamespace
  where namespace.nspname = 'policy_lab';
  if owned_policy is distinct from '09e17e1afe08f29e7daf0613742c7910' then
    raise exception 'STOP owned manifest drift: policy %', owned_policy;
  end if;

  select md5(string_agg(
      relation.relname || '.' || attribute.attname || '|' ||
      format_type(attribute.atttypid, attribute.atttypmod) || '|' ||
      attribute.attnotnull::text || '|' ||
      coalesce(pg_get_expr(attribute_default.adbin, attribute_default.adrelid), ''),
      E'\n' order by relation.relname, attribute.attnum
    ))
    into owned_column
  from pg_attribute as attribute
  join pg_class as relation on relation.oid = attribute.attrelid
  join pg_namespace as namespace on namespace.oid = relation.relnamespace
  left join pg_attrdef as attribute_default
    on attribute_default.adrelid = attribute.attrelid
   and attribute_default.adnum = attribute.attnum
  where namespace.nspname = 'policy_lab'
    and relation.relkind = 'r'
    and attribute.attnum > 0
    and not attribute.attisdropped;
  if owned_column is distinct from 'f06ed9f3f3ae1a8f415af98885130761' then
    raise exception 'STOP owned manifest drift: column %', owned_column;
  end if;

  select md5(string_agg(
      constraint_row.conname || ':' ||
      pg_temp.manifest_text(pg_get_constraintdef(constraint_row.oid)),
      '|' order by constraint_row.conname
    ))
    into owned_constraint
  from pg_constraint as constraint_row
  join pg_class as relation on relation.oid = constraint_row.conrelid
  join pg_namespace as namespace on namespace.oid = relation.relnamespace
  where namespace.nspname = 'policy_lab';
  if owned_constraint is distinct from 'e3b651e76ca74fcb9874d6cf5604de97' then
    raise exception 'STOP owned manifest drift: constraint %', owned_constraint;
  end if;

  select md5(string_agg(
      namespace.nspname || '.' || procedure.proname || '(' ||
      pg_get_function_identity_arguments(procedure.oid) || ')' || '|' ||
      md5(pg_temp.manifest_text(procedure.prosrc)) || '|' ||
      procedure.prosecdef::text || '|' ||
      procedure.provolatile::text || '|' ||
      coalesce(array_to_string(procedure.proconfig, ','), ''),
      E'\n' order by namespace.nspname, procedure.proname
    ))
    into owned_function
  from pg_proc as procedure
  join pg_namespace as namespace on namespace.oid = procedure.pronamespace
  where namespace.nspname in ('policy_lab', 'memory');
  if owned_function is distinct from 'a80cf659cfdda35753be1dec29db3968' then
    raise exception 'STOP owned manifest drift: function %', owned_function;
  end if;

  select md5(string_agg(
      relation.relname || '.' || index_relation.relname,
      E'\n' order by relation.relname, index_relation.relname
    ))
    into owned_index
  from pg_index as index_row
  join pg_class as index_relation on index_relation.oid = index_row.indexrelid
  join pg_class as relation on relation.oid = index_row.indrelid
  join pg_namespace as namespace on namespace.oid = relation.relnamespace
  where namespace.nspname = 'policy_lab';
  if owned_index is distinct from '0d734f2e701b06de229d6ef0616931b5' then
    raise exception 'STOP owned manifest drift: index %', owned_index;
  end if;

  select count(*)::int
    into owned_trigger
  from pg_trigger as trigger_row
  join pg_class as relation on relation.oid = trigger_row.tgrelid
  join pg_namespace as namespace on namespace.oid = relation.relnamespace
  where namespace.nspname = 'policy_lab'
    and not trigger_row.tgisinternal;
  if owned_trigger <> 0 then
    raise exception 'STOP owned manifest drift: trigger';
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

drop function pg_temp.manifest_text(text);

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
