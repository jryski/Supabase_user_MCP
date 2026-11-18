-- Synthetic-only storage fixtures for the M2 real-stack storage probe. Loaded after seed-m2.sql.
-- alice gets storage read and write in her existing membership; bob gets none.

insert into policy_lab.capability_grants (
  principal_id, client_id, workspace_id, capability, state, valid_until
) values
  ('11111111-1111-4111-9111-111111111111'::uuid, 'smp-lab-inspector', 'workspace-mcp-alpha', 'storage:read', 'active', '2099-01-01'),
  ('11111111-1111-4111-9111-111111111111'::uuid, 'smp-lab-inspector', 'workspace-mcp-alpha', 'storage:write', 'active', '2099-01-01')
on conflict (principal_id, client_id, workspace_id, capability) do update
set state = excluded.state,
    valid_until = excluded.valid_until;
