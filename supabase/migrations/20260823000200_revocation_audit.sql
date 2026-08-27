CREATE TABLE policy_lab.audit_events (
  event_id text PRIMARY KEY,
  recorded_at timestamptz NOT NULL,
  principal_id uuid NOT NULL REFERENCES policy_lab.principals,
  client_id text NOT NULL REFERENCES policy_lab.clients,
  workspace_id text NOT NULL,
  event_type text NOT NULL CHECK (event_type IN ('memory.read.allowed', 'memory.read.denied')),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (
    jsonb_typeof(metadata) = 'object'
    AND octet_length(metadata::text) <= 4096
    AND metadata::text !~* '"(secret|token|credential|password|authorization|cookie|payload|access[_-]?token|refresh[_-]?token)"[[:space:]]*:'
  )
);

REVOKE ALL ON policy_lab.audit_events FROM PUBLIC, anon, authenticated;
GRANT SELECT ON policy_lab.audit_events TO authenticated;

ALTER TABLE policy_lab.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_lab.audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_event_current_principal_read ON policy_lab.audit_events
  FOR SELECT TO authenticated
  USING (
    principal_id = auth.uid()
    AND client_id = auth.jwt() -> 'app_metadata' ->> 'client_id'
    AND EXISTS (
      SELECT 1
      FROM policy_lab.principals AS p
      JOIN policy_lab.clients AS c
        ON c.client_id = audit_events.client_id
      JOIN policy_lab.memberships AS m
        ON m.principal_id = audit_events.principal_id
       AND m.client_id = audit_events.client_id
       AND m.workspace_id = audit_events.workspace_id
      JOIN policy_lab.capability_grants AS g
        ON g.principal_id = m.principal_id
       AND g.client_id = m.client_id
       AND g.workspace_id = m.workspace_id
       AND g.capability = 'memory:read'
      WHERE p.principal_id = audit_events.principal_id
        AND p.identity_eligibility = 'verified'
        AND c.state = 'active'
        AND c.valid_until > now()
        AND m.state = 'active'
        AND m.valid_until > now()
        AND g.state = 'active'
        AND g.valid_until > now()
    )
  );
