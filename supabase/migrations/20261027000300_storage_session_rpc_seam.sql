-- Issue #123 S4 follow-up: the storage client's two session RPCs, reachable through the Data API
-- without exposing policy_lab. config.toml exposes public, memory, storage and extensions only;
-- policy_lab stays unexposed. These wrappers live in public, return exactly what the policy_lab
-- functions return, and run as the caller (SECURITY INVOKER), so the same RLS and grants apply.
-- Assumes option A; pending RLS layout decision.
-- Additive. Synthetic local lab only. No service role, no SECURITY DEFINER.

create function public.mcp_storage_principal_v1()
returns uuid
language sql
stable
security invoker
set search_path = ''
as $$
  select policy_lab.storage_principal();
$$;

create function public.mcp_storage_session_capabilities_v1()
returns jsonb
language sql
stable
security invoker
set search_path = ''
as $$
  select policy_lab.storage_session_capabilities();
$$;

-- Supabase default privileges grant EXECUTE on new public functions to anon, authenticated and
-- service_role. Remove them all, then grant exactly authenticated.
revoke all on function public.mcp_storage_principal_v1() from public, anon, authenticated, service_role;
revoke all on function public.mcp_storage_session_capabilities_v1()
  from public, anon, authenticated, service_role;
grant execute on function public.mcp_storage_principal_v1() to authenticated;
grant execute on function public.mcp_storage_session_capabilities_v1() to authenticated;
