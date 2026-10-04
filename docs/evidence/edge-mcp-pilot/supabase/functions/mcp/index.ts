// Supabase User MCP: Edge Function pilot, phase 1.
//
// Phase 1 scope, per ATLAS review MC1807: OAuth discovery, registration, consent and
// authentication only. Data dispatch stays fail-closed. The inbound MCP bearer is never
// sent to PostgREST or any other upstream API, and no admin or service-role client is
// constructed. Only the user-mode JWT gate (JWKS verification with pinned issuer and
// audience) is used.
import 'jsr:@supabase/functions-js@2/edge-runtime.d.ts'
import { pipeline } from 'npm:@supabase/middleware@1.0.0'
import { withOAuthProtectedResource } from 'npm:@supabase/server@1.9.0'
import { withRequiredClaims } from 'npm:@supabase/server@1.9.0/middleware/required-claims'
import { createMcpHandler, McpServer } from 'npm:@modelcontextprotocol/server@2.3.0'
import { z } from 'npm:zod@4.6.5'
import { createBounded, jsonError } from './bounded.ts'

const MAX_BODY_BYTES = 65_536
const DEADLINE_MS = 2_000

function list(name: string): string[] {
  return (Deno.env.get(name) ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value.length > 0)
}

// Pinned explicitly; never derived from the request.
const ISSUER = Deno.env.get('MCP_AUTH_ISSUER') ?? ''
const AUDIENCE = list('MCP_AUDIENCE')
const ALLOWED_CLIENTS = new Set(list('MCP_ALLOWED_CLIENT_IDS'))

function claimString(claims: Record<string, unknown>, key: string): string | null {
  const value = claims[key]
  return typeof value === 'string' && value.length > 0 ? value : null
}

const failClosed = {
  isError: true,
  content: [
    {
      type: 'text' as const,
      text: JSON.stringify({
        error: 'downstream_credential_unresolved',
        detail: 'Data access is disabled until a separate downstream credential is accepted.',
      }),
    },
  ],
}

const gated = pipeline(
  [
    withOAuthProtectedResource(),
    withRequiredClaims({ issuer: ISSUER, audience: AUDIENCE, errors: { detailed: false } }),
  ],
  async (req, ctx) => {
    const claims = ctx.jwtClaims as unknown as Record<string, unknown>
    const clientId = claimString(claims, 'client_id')
    // Ordinary first-party sessions carry no OAuth client_id; they are not MCP grants.
    if (clientId === null) return jsonError(403, 'oauth_client_required')
    if (ALLOWED_CLIENTS.size > 0 && !ALLOWED_CLIENTS.has(clientId)) {
      return jsonError(403, 'client_not_allowed')
    }
    if (claimString(claims, 'role') !== 'authenticated') return jsonError(403, 'role_not_allowed')
    const handler = createMcpHandler(
      () => {
        const server = new McpServer({ name: 'supabase-user-mcp-pilot', version: '0.0.1' })
        server.registerTool(
          'whoami',
          { description: 'Return the verified caller identity (no data access).', inputSchema: z.object({}) },
          () => ({
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  sub: claimString(claims, 'sub'),
                  client_id: clientId,
                  role: claimString(claims, 'role'),
                  aud: claims.aud ?? null,
                  iss: claimString(claims, 'iss'),
                }),
              },
            ],
          }),
        )
        server.registerTool(
          'memory_search',
          {
            description: 'Search memories (disabled in phase 1).',
            inputSchema: z.object({ query: z.string().max(256) }),
          },
          () => failClosed,
        )
        return server
      },
      { onerror: () => console.error('mcp_request_failed') },
    )
    return handler.fetch(req)
  },
)

const bounded = createBounded(gated, { maxBodyBytes: MAX_BODY_BYTES, deadlineMs: DEADLINE_MS })

function serve(req: Request): Promise<Response> {
  if (ISSUER.length === 0 || AUDIENCE.length === 0) {
    return Promise.resolve(jsonError(500, 'pilot_not_configured'))
  }
  return bounded(req)
}

Deno.serve(serve)
