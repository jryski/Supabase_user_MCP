-- SACD minimal first proof (profile v0.3 section 8), part 1: roles, schemas, tables, policies.
-- Local synthetic pilot stack only (project_id user-mcp-edge-pilot). Never apply to a hosted project.
begin;

-- Capability schema exposed to the Data API (config.toml [api] schemas) and a private schema
-- that is not exposed.
create schema mcp_api;
create schema mcp_cap;
revoke all on schema mcp_api from public;
revoke all on schema mcp_cap from public;

-- SACD-7 capability role and SACD-8 capability owner role.
create role mcp_ingress nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls;
create role mcp_capability_owner nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls;

-- The API authenticator may switch to mcp_ingress. mcp_ingress itself is a member of nothing.
grant mcp_ingress to authenticator;
grant usage on schema mcp_api to mcp_ingress;

-- Owner role: private-schema usage and narrow reads only.
grant usage on schema mcp_cap to mcp_capability_owner;

-- Server-controlled registry: approved MCP client -> exactly one canonical resource (SACD-2).
create table mcp_cap.client_registry (
  client_id text primary key,
  mcp_resource text not null,
  approved_at timestamptz not null default now()
);
-- Declared non-MCP OAuth clients: tokens left unchanged by the hook (SACD-4).
create table mcp_cap.declared_non_mcp_client (
  client_id text primary key,
  note text not null default ''
);
-- Session timeout policy evaluated by the guard. It must mirror the Auth configuration
-- ([auth.sessions] timebox and inactivity_timeout); SACD-22 drift checks compare the two.
create table mcp_cap.session_policy (
  singleton boolean primary key default true check (singleton),
  timebox interval,
  inactivity_timeout interval
);
insert into mcp_cap.session_policy (singleton) values (true);
-- Private synthetic fixture data read by the capability function.
create table mcp_cap.fixture (
  id bigint generated always as identity primary key,
  owner_sub uuid not null,
  label text not null check (octet_length(label) <= 256),
  created_at timestamptz not null default now()
);

alter table mcp_cap.client_registry enable row level security;
alter table mcp_cap.client_registry force row level security;
alter table mcp_cap.declared_non_mcp_client enable row level security;
alter table mcp_cap.declared_non_mcp_client force row level security;
alter table mcp_cap.session_policy enable row level security;
alter table mcp_cap.session_policy force row level security;
alter table mcp_cap.fixture enable row level security;
alter table mcp_cap.fixture force row level security;

revoke all on mcp_cap.client_registry, mcp_cap.declared_non_mcp_client, mcp_cap.fixture,
  mcp_cap.session_policy from public, anon, authenticated, service_role;

grant select on mcp_cap.client_registry to mcp_capability_owner, supabase_auth_admin;
grant select on mcp_cap.declared_non_mcp_client to supabase_auth_admin;
grant select on mcp_cap.fixture to mcp_capability_owner;
grant usage on schema mcp_cap to supabase_auth_admin;

create policy client_registry_owner_read on mcp_cap.client_registry
  for select to mcp_capability_owner using (true);
create policy client_registry_auth_read on mcp_cap.client_registry
  for select to supabase_auth_admin using (true);
create policy declared_non_mcp_auth_read on mcp_cap.declared_non_mcp_client
  for select to supabase_auth_admin using (true);

commit;
