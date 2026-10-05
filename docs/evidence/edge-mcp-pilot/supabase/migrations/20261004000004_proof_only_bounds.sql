-- PROOF-ONLY capabilities for bounds tests (CT-14). Not part of any real deployment; listed in
-- the access matrix as test-only. Guard first, owned by the restricted owner role.
begin;

create function mcp_api.proof_probe_v1(sleep_ms integer default 0)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  perform mcp_cap.sacd_guard();
  perform pg_catalog.pg_sleep(least(greatest(coalesce(sleep_ms, 0), 0), 10000) / 1000.0);
  return pg_catalog.jsonb_build_object(
    'statement_timeout', pg_catalog.current_setting('statement_timeout'),
    'lock_timeout', pg_catalog.current_setting('lock_timeout'),
    'role', pg_catalog.current_setting('role'));
end;
$$;

create function mcp_api.proof_lock_v1()
returns bigint
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  n bigint;
begin
  perform mcp_cap.sacd_guard();
  select count(*) into n from mcp_cap.fixture;
  return n;
end;
$$;

revoke all on function mcp_api.proof_probe_v1(integer) from public, anon, authenticated, service_role;
revoke all on function mcp_api.proof_lock_v1() from public, anon, authenticated, service_role;
grant execute on function mcp_api.proof_probe_v1(integer) to mcp_ingress;
grant execute on function mcp_api.proof_lock_v1() to mcp_ingress;

grant create on schema mcp_api to mcp_capability_owner;
grant mcp_capability_owner to postgres with inherit false, set true;
alter function mcp_api.proof_probe_v1(integer) owner to mcp_capability_owner;
alter function mcp_api.proof_lock_v1() owner to mcp_capability_owner;
revoke mcp_capability_owner from postgres;
revoke create on schema mcp_api from mcp_capability_owner;

commit;
