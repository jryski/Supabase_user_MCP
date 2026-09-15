import {
  SESSION_CAPABILITIES_DEFAULT_TTL_MS,
  SESSION_CAPABILITIES_GET_TOOL,
  SESSION_CAPABILITIES_READ_SEMANTICS_DIGEST,
  type SessionCapabilitiesGetOutput,
  type SessionVisibleTool,
} from '@supabase-user-mcp/contracts';
import {
  createReadToolExecutor,
  normalizeReadToolExecutionContext,
  type ReadToolGovernancePolicy,
  type ReadToolInvocationContext,
} from './read-tool-governor.js';

function visibleTool(name: string): SessionVisibleTool {
  return {
    name,
    access: {
      declared: 'declared',
      verified: 'unknown',
      qualified: 'unknown',
      authorized: 'unknown',
      available: 'unknown',
    },
  };
}

export function projectSessionVisibleTools(
  registeredToolNames: ReadonlySet<string>,
): SessionVisibleTool[] {
  return [...registeredToolNames].toSorted().map((name) => visibleTool(name));
}

export function buildSessionCapabilitiesOutput(
  registeredToolNames: ReadonlySet<string>,
): SessionCapabilitiesGetOutput {
  const observedAt = new Date();
  const expiresAt = new Date(observedAt.getTime() + SESSION_CAPABILITIES_DEFAULT_TTL_MS);
  const candidate = {
    ok: true,
    discovery: {
      profile: 'session_capabilities_minimal_draft_0_2',
      schema_version: 'draft-0.2',
      tools_list: { method: 'tools/list', permission_authority: false },
      status: 'DRAFT; supplements tools/list only; no runtime authority',
      observed_at: observedAt.toISOString(),
      expires_at: expiresAt.toISOString(),
      assurance: {
        tools_list_is_permission_authority: false,
        catalog_provenance_currentness: 'unknown',
        effective_grants: 'unknown',
      },
    },
    session: {
      wire: {
        max_request_id_utf8_bytes: 1024,
        max_complete_response_utf8_bytes: 65536,
        default_deadline_ms: 2000,
        automatic_retries: 0,
      },
      read_semantics_digest: SESSION_CAPABILITIES_READ_SEMANTICS_DIGEST,
    },
    visible_tools: projectSessionVisibleTools(registeredToolNames),
  };
  const parsed = SESSION_CAPABILITIES_GET_TOOL.outputSchema.safeParse(candidate);
  if (!parsed.success) {
    return SESSION_CAPABILITIES_GET_TOOL.outputSchema.parse({
      ok: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Request could not be completed.',
        retryable: false,
      },
    });
  }
  return parsed.data;
}

export interface SessionCapabilitiesGetOptions {
  readonly governance?: ReadToolGovernancePolicy;
}

export function createSessionCapabilitiesGet(
  registeredToolNames: () => ReadonlySet<string>,
  options: SessionCapabilitiesGetOptions = {},
) {
  const execute = createReadToolExecutor(
    SESSION_CAPABILITIES_GET_TOOL,
    async () => buildSessionCapabilitiesOutput(registeredToolNames()),
    options.governance,
  );
  return (invocation?: ReadToolInvocationContext) =>
    execute({}, normalizeReadToolExecutionContext(invocation));
}
