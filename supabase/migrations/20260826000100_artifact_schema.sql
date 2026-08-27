create extension if not exists "uuid-ossp";
create extension if not exists pgcrypto;

create table if not exists public.approved_inspector_clients (
  client_id text primary key,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  notes text
);

insert into public.approved_inspector_clients (client_id, active, notes)
values ('smp-lab-inspector', true, 'Lab-approved synthetic client id')
on conflict do nothing;

create table if not exists public.artifact_registry (
  artifact_id uuid primary key default gen_random_uuid(),
  principal_id uuid not null references auth.users(id) on delete restrict,
  bucket text not null,
  object_key text not null,
  byte_length bigint not null check (byte_length >= 0),
  sha256_full bytea not null,
  merkle_root bytea not null,
  chunk_size int not null check (chunk_size > 0),
  chunk_count int not null check (chunk_count >= 0),
  content_type text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz
);

create unique index if not exists artifact_registry_bucket_object_key_idx
  on public.artifact_registry (bucket, object_key);

create table if not exists public.artifact_chunks (
  artifact_id uuid not null references public.artifact_registry(artifact_id) on delete cascade,
  chunk_index int not null check (chunk_index >= 0),
  byte_start bigint not null check (byte_start >= 0),
  byte_length int not null check (byte_length >= 0),
  sha256 bytea not null,
  primary key (artifact_id, chunk_index)
);

create table if not exists public.artifact_derivations (
  derivation_id uuid primary key default gen_random_uuid(),
  derived_artifact_id uuid not null references public.artifact_registry(artifact_id) on delete cascade,
  derivation_type text not null,
  profile_id text not null,
  profile_version text not null,
  scope text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.derivation_inputs (
  derivation_id uuid not null references public.artifact_derivations(derivation_id) on delete cascade,
  source_artifact_id uuid not null references public.artifact_registry(artifact_id) on delete cascade,
  source_sha256 bytea not null,
  primary key (derivation_id, source_artifact_id)
);

alter table public.artifact_registry enable row level security;
alter table public.artifact_chunks enable row level security;
alter table public.artifact_derivations enable row level security;
alter table public.derivation_inputs enable row level security;
alter table public.approved_inspector_clients enable row level security;

revoke all on public.approved_inspector_clients from anon, authenticated;
grant select on public.approved_inspector_clients to authenticated;

create policy approved_inspector_clients_select_current
  on public.approved_inspector_clients
  for select
  to authenticated
  using (
    active
    and client_id = coalesce(
      auth.jwt() ->> 'client_id',
      auth.jwt() #>> '{app_metadata,client_id}'
    )
  );

create policy artifact_registry_select_authenticated
  on public.artifact_registry
  for select
  to authenticated
  using (
    principal_id = auth.uid()
    and (expires_at is null or expires_at > now())
  );

create policy artifact_chunks_select_authenticated
  on public.artifact_chunks
  for select
  to authenticated
  using (
    exists (
      select 1
      from public.artifact_registry ar
      where ar.artifact_id = artifact_chunks.artifact_id
        and ar.principal_id = auth.uid()
        and (ar.expires_at is null or ar.expires_at > now())
    )
  );

create policy artifact_derivations_select_authenticated
  on public.artifact_derivations
  for select
  to authenticated
  using (
    exists (
      select 1
      from public.artifact_registry ar
      where ar.artifact_id = artifact_derivations.derived_artifact_id
        and ar.principal_id = auth.uid()
        and (ar.expires_at is null or ar.expires_at > now())
    )
  );

create policy derivation_inputs_select_authenticated
  on public.derivation_inputs
  for select
  to authenticated
  using (
    exists (
      select 1
      from public.artifact_derivations d
      join public.artifact_registry ar on ar.artifact_id = d.derived_artifact_id
      where d.derivation_id = derivation_inputs.derivation_id
        and ar.principal_id = auth.uid()
        and (ar.expires_at is null or ar.expires_at > now())
    )
  );

-- Append-only: no UPDATE/DELETE for non-owner roles.
revoke update, delete on public.artifact_registry from anon, authenticated, service_role;
revoke update, delete on public.artifact_chunks from anon, authenticated, service_role;
revoke update, delete on public.artifact_derivations from anon, authenticated, service_role;
revoke update, delete on public.derivation_inputs from anon, authenticated, service_role;
