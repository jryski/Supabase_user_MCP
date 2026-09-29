/**
 * Pure decision oracle for the uninstalled hook v2 packet.
 * No network, no database, and no credential values.
 * A failed liveness check is a per-call denial. It is not a revocation receipt.
 */

const NIL_UUID = '00000000-0000-0000-0000-000000000000';
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isNonNilUuid(value) {
  return (
    typeof value === 'string' && value.toLowerCase() !== NIL_UUID && UUID_PATTERN.test(value)
  );
}

export function scopeHasOpenId(scope) {
  const parts = [];
  if (typeof scope === 'string') parts.push(...scope.split(/\s+/u));
  else if (Array.isArray(scope)) parts.push(...scope);
  return parts.some((item) => typeof item === 'string' && item.toLowerCase() === 'openid');
}

function eventScope(event, claims) {
  if (claims.scope !== undefined) return claims.scope;
  return event.scope;
}

function liveSession(sessions, sessionId, userId, now) {
  if (!isNonNilUuid(sessionId) || typeof userId !== 'string' || userId.length === 0) return false;
  const row = sessions.find((item) => item.id === sessionId);
  if (row === undefined || row.userId !== userId) return false;
  if (row.notAfter === null || row.notAfter === undefined) return true;
  const expires = Date.parse(row.notAfter);
  return Number.isFinite(expires) && expires > now;
}

function raise(reason) {
  return {
    action: 'raise',
    reason,
    revocationClaimed: false,
    liveCheck: 'per_call_source_session',
  };
}

/**
 * @param {object} input
 * @param {object} input.event GoTrue hook event. `claims.client_id` is the only client id.
 * @param {readonly {clientId: string, mcpResource: string, agentId: string}[]} input.clients
 * @param {readonly {id: string, userId: string, notAfter?: string | null}[]} input.sessions
 * @param {() => string} input.randomUuid
 * @param {number} [input.now]
 */
export function decideHookV2(input) {
  const event = input.event;
  const claims = event === null || typeof event !== 'object' ? undefined : event.claims;
  if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) {
    return raise('hook_event_unreadable');
  }
  const clientId = typeof claims.client_id === 'string' ? claims.client_id : '';
  if (clientId.length === 0) {
    return {
      action: 'unchanged',
      reason: 'absent_client_id',
      claims,
      revocationClaimed: false,
      liveCheck: 'not_applicable',
    };
  }
  if (scopeHasOpenId(eventScope(event, claims))) return raise('openid_scope_refused');
  const mapped = input.clients.find((row) => row.clientId === clientId);
  if (mapped === undefined) return raise('unmapped_client_id');
  const sourceSessionId = typeof claims.session_id === 'string' ? claims.session_id : '';
  const now = input.now ?? Date.now();
  if (!liveSession(input.sessions, sourceSessionId, event.user_id, now)) {
    return raise('source_session_not_live');
  }
  const fresh = input.randomUuid();
  if (!isNonNilUuid(fresh) || input.sessions.some((row) => row.id === fresh)) {
    return raise('fresh_session_id_rejected');
  }
  return {
    action: 'map',
    reason: 'mapped_client',
    revocationClaimed: false,
    liveCheck: 'per_call_source_session',
    claims: {
      ...claims,
      aud: mapped.mcpResource,
      role: 'mcp_ingress',
      session_id: fresh,
      source_session_id: sourceSessionId,
      agent_id: mapped.agentId,
    },
  };
}
