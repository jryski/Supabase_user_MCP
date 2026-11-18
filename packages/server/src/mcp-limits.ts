import { MAX_RESPONSE_BYTES } from '@supabase-user-mcp/contracts';

/**
 * Explicit MCP SDK input limits (GHSA-46jr-4wx8-v453).
 *
 * `@modelcontextprotocol/server` 2.3.0+ can bound both values, but the element
 * bound is off by default and the body bound defaults to 4 MiB. This server
 * sets both on every MCP server and HTTP handler it builds.
 */

/**
 * Largest MCP HTTP request body, in bytes. Passed as `maxRequestBodySize` to
 * every `createMcpHandler`. Matches the native ingress cap, so a body the
 * ingress accepts is never larger than this. stdio has no request body.
 */
export const MCP_MAX_REQUEST_BODY_BYTES = MAX_RESPONSE_BYTES;

/**
 * Largest combined count of array elements and object members in one
 * `tools/call` `arguments` payload. Passed as `maxToolInputElements` to every
 * `McpServer`. The largest valid input (memory_search with every field and the
 * full filter allowance) has 11; strict schemas reject anything wider. The
 * bound leaves room without admitting wide payloads.
 */
export const MCP_MAX_TOOL_INPUT_ELEMENTS = 32;
