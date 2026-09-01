export const EXPECTED_MEMORY_POSTGREST_PATHS = Object.freeze([
  '/',
  '/rpc/authorized_memory_get_v1',
  '/rpc/authorized_memory_list_recent_v1',
  '/rpc/authorized_memory_search_v1',
] as const);

export interface PostgrestSurfaceCensus {
  readonly advertisedPaths: typeof EXPECTED_MEMORY_POSTGREST_PATHS;
}

export function parseExpectedMemoryPostgrestSurface(text: string): PostgrestSurfaceCensus {
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    throw new TypeError('PostgREST OpenAPI response is not valid JSON.');
  }
  return assertExpectedMemoryPostgrestSurface(document);
}

export function assertExpectedMemoryPostgrestSurface(document: unknown): PostgrestSurfaceCensus {
  if (typeof document !== 'object' || document === null || !('paths' in document)) {
    throw new TypeError('PostgREST OpenAPI document is malformed.');
  }
  const paths = (document as { paths?: unknown }).paths;
  if (typeof paths !== 'object' || paths === null || Array.isArray(paths)) {
    throw new TypeError('PostgREST OpenAPI document is malformed.');
  }

  const advertisedPaths = Object.keys(paths).toSorted();
  const expectedPaths = [...EXPECTED_MEMORY_POSTGREST_PATHS];
  if (
    advertisedPaths.length !== expectedPaths.length ||
    advertisedPaths.some((path, index) => path !== expectedPaths[index])
  ) {
    throw new Error('PostgREST advertised surface does not match the fixed memory allowlist.');
  }

  return Object.freeze({ advertisedPaths: EXPECTED_MEMORY_POSTGREST_PATHS });
}
