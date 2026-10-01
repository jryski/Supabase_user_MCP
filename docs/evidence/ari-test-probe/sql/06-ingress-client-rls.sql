-- F1 marker RLS for Ari TEST only.
-- This file is not a supabase/migration. This agent does not apply it and
-- does not contact hosted TEST.
--
-- N21: F1 here covers public.ari_probe_marker only. Production F1 is every
-- protected surface. This file does not add policies on Auth, Storage,
-- GraphQL, Realtime, or any other table.
--
-- The restrictive policy rejects authenticated JWTs whose client_id equals
-- a parameterized A OAuth client. The client ids are batch settings, not
-- literals in this file.
--
-- Confirm the dashboard ref is odbcejsuuqdzhabjmozi. Forbidden:
-- lygftpbjgqgvuunkwnxf and any HOUSE, VAULT, or production project.
--
-- N8: one SQL-editor batch. Paste these at the top of the same batch:
--   select set_config('ari.project_ref', 'odbcejsuuqdzhabjmozi', false);
--   select set_config('ari.oauth_client_id', '<baseline A client id>', false);
--   select set_config('ari.external_a_client_id', '<external A client id>', false);
-- Prerequisite: sql/01 marker table. Do not recreate the synthetic user.
--
-- Rollback, controller only, on this TEST ref:
--   drop policy if exists ari_probe_marker_reject_a_client on public.ari_probe_marker;

begin;

do $target$
declare
  project_ref text := current_setting('ari.project_ref', true);
  allowed_ref constant text := 'odbcejsuuqdzhabjmozi';
  forbidden_ref constant text := 'lygftpbjgqgvuunkwnxf';
  v_baseline text := current_setting('ari.oauth_client_id', true);
  v_external text := current_setting('ari.external_a_client_id', true);
  client_pattern constant text := '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$';
begin
  if project_ref is not distinct from forbidden_ref
    or coalesce(project_ref, '') = ''
    or project_ref is distinct from allowed_ref
  then
    raise exception
      'refusing marker F1 SQL for project ref %; production, HOUSE, and VAULT are forbidden',
      coalesce(project_ref, '<unset>');
  end if;

  if to_regclass('public.ari_probe_marker') is null then
    raise exception 'public.ari_probe_marker is missing; apply sql/01 first';
  end if;

  if v_baseline is null
    or v_external is null
    or v_baseline !~ client_pattern
    or v_external !~ client_pattern
    or v_baseline = v_external
  then
    raise exception 'A client id parameters must be distinct registered client ids';
  end if;

  -- N21: marker table only. The client ids are parameters, quoted as literals.
  execute 'drop policy if exists ari_probe_marker_reject_a_client on public.ari_probe_marker';
  execute format(
    $policy$
      create policy ari_probe_marker_reject_a_client
        on public.ari_probe_marker
        as restrictive
        for select
        to authenticated
        using (
          coalesce(auth.jwt() ->> 'client_id', '') is distinct from %L
          and coalesce(auth.jwt() ->> 'client_id', '') is distinct from %L
        )
    $policy$,
    v_baseline,
    v_external
  );
end;
$target$;

commit;
