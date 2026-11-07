/**
 * Release-owned ADR-0007 approval data, compiled into the installed package.
 * There is deliberately no runtime path, environment override or discovery.
 * A reviewed release must add each exact (ADR, descriptor-body digest) pair.
 * Empty by default: this candidate approves no application capability.
 */
export const COMPILED_CAPABILITY_APPROVALS = Object.freeze({
  allowlistVersion: 'supabase-user-mcp.capability-approvals.v1',
  approvals: Object.freeze([]),
});
