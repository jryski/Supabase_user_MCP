INSERT INTO policy_lab.principals (principal_id, principal_kind, identity_eligibility) VALUES
  ('00000000-0000-0000-0000-000000000001', 'human', 'verified'),
  ('00000000-0000-0000-0000-000000000002', 'human', 'verified'),
  ('00000000-0000-0000-0000-000000000003', 'human', 'denied');

INSERT INTO policy_lab.clients (client_id, state, valid_until) VALUES
  ('client-active', 'active', '2099-01-01'),
  ('client-other', 'active', '2099-01-01'),
  ('client-expired', 'expired', '2020-01-01'),
  ('client-revoked', 'revoked', '2099-01-01');

INSERT INTO policy_lab.memberships (principal_id, client_id, workspace_id, state, valid_until) VALUES
  ('00000000-0000-0000-0000-000000000001', 'client-active', 'workspace-alpha', 'active', '2099-01-01'),
  ('00000000-0000-0000-0000-000000000001', 'client-active', 'workspace-no-grant', 'active', '2099-01-01'),
  ('00000000-0000-0000-0000-000000000001', 'client-active', 'workspace-membership-expired', 'expired', '2020-01-01'),
  ('00000000-0000-0000-0000-000000000001', 'client-active', 'workspace-membership-revoked', 'revoked', '2099-01-01'),
  ('00000000-0000-0000-0000-000000000001', 'client-expired', 'workspace-client-expired', 'active', '2099-01-01'),
  ('00000000-0000-0000-0000-000000000001', 'client-revoked', 'workspace-client-revoked', 'active', '2099-01-01'),
  ('00000000-0000-0000-0000-000000000002', 'client-other', 'workspace-beta', 'active', '2099-01-01'),
  ('00000000-0000-0000-0000-000000000003', 'client-active', 'workspace-denied-principal', 'active', '2099-01-01');

INSERT INTO policy_lab.capability_grants (principal_id, client_id, workspace_id, capability, state, valid_until) VALUES
  ('00000000-0000-0000-0000-000000000001', 'client-active', 'workspace-alpha', 'memory:read', 'active', '2099-01-01'),
  ('00000000-0000-0000-0000-000000000001', 'client-active', 'workspace-membership-expired', 'memory:read', 'active', '2099-01-01'),
  ('00000000-0000-0000-0000-000000000001', 'client-active', 'workspace-membership-revoked', 'memory:read', 'active', '2099-01-01'),
  ('00000000-0000-0000-0000-000000000001', 'client-active', 'workspace-grant-expired', 'memory:read', 'expired', '2020-01-01'),
  ('00000000-0000-0000-0000-000000000001', 'client-active', 'workspace-grant-revoked', 'memory:read', 'revoked', '2099-01-01'),
  ('00000000-0000-0000-0000-000000000001', 'client-expired', 'workspace-client-expired', 'memory:read', 'active', '2099-01-01'),
  ('00000000-0000-0000-0000-000000000001', 'client-revoked', 'workspace-client-revoked', 'memory:read', 'active', '2099-01-01'),
  ('00000000-0000-0000-0000-000000000002', 'client-other', 'workspace-beta', 'memory:read', 'active', '2099-01-01'),
  ('00000000-0000-0000-0000-000000000003', 'client-active', 'workspace-denied-principal', 'memory:read', 'active', '2099-01-01');

INSERT INTO policy_lab.memberships (principal_id, client_id, workspace_id, state, valid_until) VALUES
  ('00000000-0000-0000-0000-000000000001', 'client-active', 'workspace-grant-expired', 'active', '2099-01-01'),
  ('00000000-0000-0000-0000-000000000001', 'client-active', 'workspace-grant-revoked', 'active', '2099-01-01');

INSERT INTO policy_lab.memories (memory_id, workspace_id, title) VALUES
  ('memory-alpha', 'workspace-alpha', 'Alpha synthetic memory'),
  ('memory-no-grant', 'workspace-no-grant', 'No grant synthetic memory'),
  ('memory-membership-expired', 'workspace-membership-expired', 'Expired membership memory'),
  ('memory-membership-revoked', 'workspace-membership-revoked', 'Revoked membership memory'),
  ('memory-grant-expired', 'workspace-grant-expired', 'Expired grant memory'),
  ('memory-grant-revoked', 'workspace-grant-revoked', 'Revoked grant memory'),
  ('memory-client-expired', 'workspace-client-expired', 'Expired client memory'),
  ('memory-client-revoked', 'workspace-client-revoked', 'Revoked client memory'),
  ('memory-beta', 'workspace-beta', 'Beta synthetic memory'),
  ('memory-denied-principal', 'workspace-denied-principal', 'Denied principal memory');

INSERT INTO policy_lab.audit_events (
  event_id, recorded_at, principal_id, client_id, workspace_id, event_type, metadata
) VALUES
  ('audit-active', '2026-08-23T12:00:00Z', '00000000-0000-0000-0000-000000000001', 'client-active', 'workspace-alpha', 'memory.read.allowed', '{"outcome":"allowed","resource_kind":"synthetic_memory"}'),
  ('audit-client-revoked', '2026-08-23T12:01:00Z', '00000000-0000-0000-0000-000000000001', 'client-revoked', 'workspace-client-revoked', 'memory.read.denied', '{"outcome":"denied","reason":"client_revoked"}'),
  ('audit-membership-revoked', '2026-08-23T12:02:00Z', '00000000-0000-0000-0000-000000000001', 'client-active', 'workspace-membership-revoked', 'memory.read.denied', '{"outcome":"denied","reason":"membership_revoked"}'),
  ('audit-grant-revoked', '2026-08-23T12:03:00Z', '00000000-0000-0000-0000-000000000001', 'client-active', 'workspace-grant-revoked', 'memory.read.denied', '{"outcome":"denied","reason":"grant_revoked"}'),
  ('audit-other-principal', '2026-08-23T12:04:00Z', '00000000-0000-0000-0000-000000000002', 'client-other', 'workspace-beta', 'memory.read.allowed', '{"outcome":"allowed","resource_kind":"synthetic_memory"}');
