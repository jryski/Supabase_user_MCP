import * as z from 'zod/v4';

export const COMPATIBILITY_PROBE_TOOL_NAME = 'system_compatibility_probe';

export const CompatibilityProbeInputSchema = z
  .object({
    probe: z.literal('m0').describe('Fixed M0 probe value.'),
  })
  .strict();

export const CompatibilityProbeOutputSchema = z
  .object({
    status: z.literal('ok'),
    milestone: z.literal('M0'),
    protocolTarget: z.literal('2026-07-28'),
    dataAccess: z.literal(false),
    networkAccess: z.literal(false),
    writeAccess: z.literal(false),
  })
  .strict();

export type CompatibilityProbeInput = z.infer<typeof CompatibilityProbeInputSchema>;
export type CompatibilityProbeOutput = z.infer<typeof CompatibilityProbeOutputSchema>;

export const COMPATIBILITY_PROBE_TOOL = Object.freeze({
  name: COMPATIBILITY_PROBE_TOOL_NAME,
  title: 'System compatibility probe',
  description:
    'Verifies the M0 MCP contract without reading data, writing data, or making network requests.',
  capability: 'system:probe',
  inputSchema: CompatibilityProbeInputSchema,
  outputSchema: CompatibilityProbeOutputSchema,
});
