import type { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';

/** Fixed PostgREST read. F1 covers this marker table only. */
export const ARI_TEST_MARKER_TOOL_NAME = 'ari_test_marker_get' as const;
export const ARI_TEST_MARKER_PATH = '/rest/v1/ari_probe_marker?select=marker' as const;
export const ARI_TEST_MARKER_PROFILE = 'TEST_ONLY' as const;

const AriTestMarkerInputSchema = z.object({}).strict();
const AriTestMarkerOutputSchema = z
  .object({
    marker: z.string().min(1).max(256),
  })
  .strict();

export interface AriTestMarkerSeam {
  readonly readMarker: (signal: AbortSignal) => Promise<string>;
}

const MARKER_UNAVAILABLE = 'ari_test_marker_unavailable';

/**
 * GET the TEST marker with the supplied bearer. The caller passes Token B.
 * The path and method are fixed.
 */
export async function readAriTestMarker(input: {
  readonly origin: string;
  readonly accessToken: string;
  readonly publishableKey: string;
  readonly fetch?: typeof globalThis.fetch;
  readonly signal?: AbortSignal;
}): Promise<string> {
  if (input.accessToken.length === 0 || input.publishableKey.length === 0) {
    throw new Error(MARKER_UNAVAILABLE);
  }
  let target: URL;
  try {
    target = new URL(ARI_TEST_MARKER_PATH, input.origin);
  } catch {
    throw new Error(MARKER_UNAVAILABLE);
  }
  if (target.pathname !== '/rest/v1/ari_probe_marker' || target.search !== '?select=marker') {
    throw new Error(MARKER_UNAVAILABLE);
  }
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  input.signal?.addEventListener('abort', onAbort, { once: true });
  if (input.signal?.aborted) controller.abort();
  const timer = setTimeout(onAbort, 5_000);
  try {
    const response = await (input.fetch ?? globalThis.fetch)(target, {
      method: 'GET',
      redirect: 'error',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${input.accessToken}`,
        apikey: input.publishableKey,
      },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(MARKER_UNAVAILABLE);
    const parsed: unknown = JSON.parse(await response.text());
    if (!Array.isArray(parsed) || parsed.length !== 1) throw new Error(MARKER_UNAVAILABLE);
    const row = parsed[0];
    if (typeof row !== 'object' || row === null || Array.isArray(row)) {
      throw new Error(MARKER_UNAVAILABLE);
    }
    const marker = (row as { marker?: unknown }).marker;
    if (typeof marker !== 'string' || marker.length === 0 || marker.length > 256) {
      throw new Error(MARKER_UNAVAILABLE);
    }
    return marker;
  } finally {
    clearTimeout(timer);
    input.signal?.removeEventListener('abort', onAbort);
  }
}

export function registerAriTestMarkerTool(server: McpServer, seam: AriTestMarkerSeam): void {
  server.registerTool(
    ARI_TEST_MARKER_TOOL_NAME,
    {
      title: 'Ari TEST marker',
      description:
        'TEST-only read of public.ari_probe_marker. Not a default CLI tool. F1 on this table does not cover other surfaces.',
      inputSchema: AriTestMarkerInputSchema,
      outputSchema: AriTestMarkerOutputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (_input, context) => {
      try {
        const marker = await seam.readMarker(context.mcpReq.signal);
        const structured = AriTestMarkerOutputSchema.parse({ marker });
        return {
          content: [{ type: 'text' as const, text: structured.marker }],
          structuredContent: structured,
        };
      } catch {
        return {
          isError: true,
          content: [{ type: 'text' as const, text: MARKER_UNAVAILABLE }],
        };
      }
    },
  );
}
