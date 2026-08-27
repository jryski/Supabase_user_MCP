create or replace function public.has_approved_inspector_client()
returns boolean
language sql
stable
set search_path = ''
as $$
  select exists (
    select 1
    from public.approved_inspector_clients c
    where c.client_id = coalesce(
      auth.jwt() ->> 'client_id',
      auth.jwt() #>> '{app_metadata,client_id}'
    )
      and c.active
  );
$$;

create or replace function public.visible_artifact_object(
  target_bucket text,
  target_object_key text
)
returns boolean
language sql
stable
set search_path = ''
as $$
  select exists (
    select 1
    from public.artifact_registry ar
    where target_bucket = 'artifact-lab'
      and ar.bucket = target_bucket
      and ar.object_key = target_object_key
      and ar.principal_id = auth.uid()
      and (ar.expires_at is null or ar.expires_at > now())
  );
$$;

revoke execute on function public.has_approved_inspector_client() from public;
revoke execute on function public.visible_artifact_object(text, text) from public;
grant execute on function public.has_approved_inspector_client() to authenticated;
grant execute on function public.visible_artifact_object(text, text) to authenticated;

create policy artifact_storage_get_only
  on storage.objects
  for select
  to authenticated
  using (
    storage.allow_only_operation('object.get_authenticated')
      and public.has_approved_inspector_client()
      and public.visible_artifact_object(bucket_id, name)
  );

-- Lab-only fixture loading. The claim is set only on a synthetic local Auth user.
create policy artifact_storage_fixture_upload
  on storage.objects
  for insert
  to authenticated
  with check (
    bucket_id in ('artifact-lab', 'artifact-outside')
    and auth.jwt() #>> '{app_metadata,s1_fixture_loader}' = 'true'
  );
