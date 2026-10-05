-- Synthetic positive-control application table in an exposed schema. Ordinary authenticated
-- users may read their own rows; it proves the denial routes used for SACD tokens are real.
begin;
create table public.app_notes (
  id bigint generated always as identity primary key,
  owner_sub uuid not null default auth.uid(),
  body text not null
);
alter table public.app_notes enable row level security;
revoke all on public.app_notes from public, anon, mcp_ingress;
grant select on public.app_notes to authenticated;
create policy app_notes_own on public.app_notes for select to authenticated
  using (owner_sub = (select auth.uid()));
create function public.app_ping() returns text language sql stable set search_path = '' as $$ select 'pong'::text $$;
revoke execute on function public.app_ping() from public;
grant execute on function public.app_ping() to authenticated;
commit;
