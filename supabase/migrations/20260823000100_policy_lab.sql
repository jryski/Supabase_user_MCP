CREATE SCHEMA policy_lab;

REVOKE ALL ON SCHEMA policy_lab FROM PUBLIC, anon, authenticated;
GRANT USAGE ON SCHEMA policy_lab TO authenticated;

CREATE TABLE policy_lab.principals (
  principal_id uuid PRIMARY KEY,
  principal_kind text NOT NULL CHECK (principal_kind IN ('human', 'delegated_agent', 'service_agent', 'reviewer', 'system_worker')),
  identity_eligibility text NOT NULL CHECK (identity_eligibility IN ('verified', 'denied'))
);

CREATE TABLE policy_lab.clients (
  client_id text PRIMARY KEY,
  state text NOT NULL CHECK (state IN ('active', 'expired', 'revoked')),
  valid_until timestamptz NOT NULL
);

CREATE TABLE policy_lab.memberships (
  principal_id uuid NOT NULL REFERENCES policy_lab.principals,
  client_id text NOT NULL REFERENCES policy_lab.clients,
  workspace_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('active', 'expired', 'revoked')),
  valid_until timestamptz NOT NULL,
  PRIMARY KEY (principal_id, client_id, workspace_id)
);

CREATE TABLE policy_lab.capability_grants (
  principal_id uuid NOT NULL REFERENCES policy_lab.principals,
  client_id text NOT NULL REFERENCES policy_lab.clients,
  workspace_id text NOT NULL,
  capability text NOT NULL CHECK (capability IN ('memory:search', 'memory:read')),
  state text NOT NULL CHECK (state IN ('active', 'expired', 'revoked')),
  valid_until timestamptz NOT NULL,
  PRIMARY KEY (principal_id, client_id, workspace_id, capability)
);

CREATE TABLE policy_lab.memories (
  memory_id text PRIMARY KEY,
  workspace_id text NOT NULL,
  title text NOT NULL
);

REVOKE ALL ON ALL TABLES IN SCHEMA policy_lab FROM PUBLIC, anon, authenticated;
GRANT SELECT ON ALL TABLES IN SCHEMA policy_lab TO authenticated;

ALTER TABLE policy_lab.principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_lab.principals FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_lab.clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_lab.clients FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_lab.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_lab.memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_lab.capability_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_lab.capability_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_lab.memories ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_lab.memories FORCE ROW LEVEL SECURITY;

CREATE POLICY principal_is_verified_subject ON policy_lab.principals
  FOR SELECT TO authenticated
  USING (principal_id = auth.uid() AND identity_eligibility = 'verified');

CREATE POLICY client_is_active_claim ON policy_lab.clients
  FOR SELECT TO authenticated
  USING (
    client_id = auth.jwt() -> 'app_metadata' ->> 'client_id'
    AND state = 'active'
    AND valid_until > now()
  );

CREATE POLICY membership_is_active_context ON policy_lab.memberships
  FOR SELECT TO authenticated
  USING (
    principal_id = auth.uid()
    AND client_id = auth.jwt() -> 'app_metadata' ->> 'client_id'
    AND state = 'active'
    AND valid_until > now()
  );

CREATE POLICY grant_is_active_context ON policy_lab.capability_grants
  FOR SELECT TO authenticated
  USING (
    principal_id = auth.uid()
    AND client_id = auth.jwt() -> 'app_metadata' ->> 'client_id'
    AND capability = 'memory:read'
    AND state = 'active'
    AND valid_until > now()
  );

CREATE POLICY memory_read_intersection ON policy_lab.memories
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1
      FROM policy_lab.principals AS p
      JOIN policy_lab.clients AS c
        ON c.client_id = auth.jwt() -> 'app_metadata' ->> 'client_id'
      JOIN policy_lab.memberships AS m
        ON m.principal_id = p.principal_id
       AND m.client_id = c.client_id
       AND m.workspace_id = memories.workspace_id
      JOIN policy_lab.capability_grants AS g
        ON g.principal_id = p.principal_id
       AND g.client_id = c.client_id
       AND g.workspace_id = m.workspace_id
       AND g.capability = 'memory:read'
      WHERE p.principal_id = auth.uid()
        AND p.identity_eligibility = 'verified'
        AND c.state = 'active'
        AND c.valid_until > now()
        AND m.state = 'active'
        AND m.valid_until > now()
        AND g.state = 'active'
        AND g.valid_until > now()
    )
  );

CREATE VIEW public.policy_lab_memory_read
WITH (security_invoker = true, security_barrier = true)
AS SELECT memory_id, title FROM policy_lab.memories;

REVOKE ALL ON public.policy_lab_memory_read FROM PUBLIC, anon;
GRANT SELECT ON public.policy_lab_memory_read TO authenticated;
