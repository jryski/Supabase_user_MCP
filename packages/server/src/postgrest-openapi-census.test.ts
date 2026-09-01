import { describe, expect, it } from 'vitest';

import {
  assertExpectedMemoryPostgrestSurface,
  EXPECTED_MEMORY_POSTGREST_PATHS,
  parseExpectedMemoryPostgrestSurface,
} from './postgrest-openapi-census.js';

describe('authenticated PostgREST OpenAPI surface census', () => {
  it('accepts only root introspection and the three named memory RPC paths', () => {
    const document = {
      swagger: '2.0',
      paths: Object.fromEntries(EXPECTED_MEMORY_POSTGREST_PATHS.map((path) => [path, {}])),
    };

    expect(assertExpectedMemoryPostgrestSurface(document)).toEqual({
      advertisedPaths: EXPECTED_MEMORY_POSTGREST_PATHS,
    });
  });

  it.each(['/memories', '/rpc/unintended_write'])('fails closed when %s is advertised', (path) => {
    const document = {
      swagger: '2.0',
      paths: {
        ...Object.fromEntries(EXPECTED_MEMORY_POSTGREST_PATHS.map((path) => [path, {}])),
        [path]: { get: {} },
      },
    };

    expect(() => assertExpectedMemoryPostgrestSurface(document)).toThrowError(
      'PostgREST advertised surface does not match the fixed memory allowlist.',
    );
  });

  it('fails closed when a named RPC is absent', () => {
    const paths = Object.fromEntries(EXPECTED_MEMORY_POSTGREST_PATHS.map((path) => [path, {}]));
    delete paths['/rpc/authorized_memory_search_v1'];

    expect(() => assertExpectedMemoryPostgrestSurface({ swagger: '2.0', paths })).toThrowError(
      'PostgREST advertised surface does not match the fixed memory allowlist.',
    );
  });

  it.each([null, [], { swagger: '2.0' }])('rejects malformed OpenAPI input', (document) => {
    expect(() => assertExpectedMemoryPostgrestSurface(document)).toThrowError(
      'PostgREST OpenAPI document is malformed.',
    );
  });

  it('rejects a non-JSON OpenAPI response without echoing its body', () => {
    expect(() =>
      parseExpectedMemoryPostgrestSurface('<html>sensitive upstream body</html>'),
    ).toThrowError('PostgREST OpenAPI response is not valid JSON.');
  });
});
