import { createHash } from 'node:crypto';

import type { McpServer } from '@modelcontextprotocol/server';
import {
  ARTIFACT_READ_LINES_TOOL,
  ARTIFACT_READ_RANGE_TOOL,
  ARTIFACT_STAT_TOOL,
  type ArtifactInspectionOperation,
  createArtifactInspectionError,
  createArtifactInspectionMcpResult,
  MAX_ARTIFACT_REQUEST_ID_BYTES,
  MAX_ARTIFACT_RESPONSE_BYTES,
  MAX_ARTIFACT_TOOL_EXECUTION_MS,
  MAX_REQUEST_ID_BYTES,
  MAX_RESPONSE_BYTES,
} from '@supabase-user-mcp/contracts';

import {
  type ArtifactInspectorDependencies,
  type ArtifactInspectorOperationalEvent,
  type ArtifactInspectorTrustedContext,
  createArtifactInspector,
  createArtifactInspectorTrustedContext,
} from './artifact-inspector.js';

export interface ArtifactMcpRegistrationConfig {
  readonly dependencies: ArtifactInspectorDependencies;
  readonly inspectorClientRef: string;
  readonly inspectorCapabilityRef: {
    readonly capability: 'artifact:inspect';
    readonly ref: string;
  };
  readonly verifierAudience: string;
  readonly policyVersion: string;
  readonly inspectorDeploymentGitCoordinate: string;
}

const ARTIFACT_REGISTRATION_CONFIG_KEYS = Object.freeze([
  'dependencies',
  'inspectorClientRef',
  'inspectorCapabilityRef',
  'verifierAudience',
  'policyVersion',
  'inspectorDeploymentGitCoordinate',
] as const);

const ARTIFACT_DEPENDENCY_KEYS = Object.freeze([
  'resolveAuthorizedArtifact',
  'readVersionedRange',
  'now',
  'emitOperationalEvent',
  'emitInspectionReceipt',
] as const);

const EXPECTED_ARTIFACT_STORAGE_CLOSURE_MANIFEST = {
  version: 'artifact-storage-closure/0.1',
  plane: 'Supabase Storage byte custody',
  authorization: {
    resolver: 'injected resolveAuthorizedArtifact',
    principal: 'verified principal',
    inspectorClient: 'approved inspector client',
    capabilityGrant: 'approved artifact:inspect capability grant',
    currentPolicyEvaluation: 'required for every call',
    historicalReceipts: 'evidence, not authorization',
  },
  resolution: {
    input: 'opaque artifact ID only',
    internalLocator: 'adapter-only, never tool input/output/receipt/event',
  },
  byteRead: {
    dependency: 'injected exact-version readVersionedRange only',
    versionBinding: 'immutable objectVersionRef equality',
    integrity: 'S1b source/raw chunk/domain-separated leaf/Merkle verification',
  },
  operations: [
    { name: 'artifact_stat', byteReadClass: 'zero byte reads' },
    { name: 'artifact_read_range', byteReadClass: 'one bounded covering read' },
    { name: 'artifact_read_lines', byteReadClass: 'one bounded complete-source read' },
  ],
  retries: 0,
  writes: 'none',
  directListingEnumeration: 'none',
  signedUrls: 'none',
  privilegedCredentials: 'prohibited, including service_role',
  unregisteredOperations: [
    'artifact_read_heading',
    'artifact_search_exact',
    'artifact_ingest',
    'artifact_semantic_analysis',
    'artifact_write',
  ],
} as const;

function deepFreeze<T>(value: T): T {
  if (value !== null && (typeof value === 'object' || typeof value === 'function')) {
    if (!Object.isFrozen(value)) {
      Object.freeze(value);
      for (const key of Reflect.ownKeys(value)) {
        deepFreeze((value as Record<PropertyKey, unknown>)[key]);
      }
    }
  }
  return value;
}

export const ARTIFACT_STORAGE_CLOSURE_MANIFEST = deepFreeze(
  EXPECTED_ARTIFACT_STORAGE_CLOSURE_MANIFEST,
);
export type ArtifactStorageClosureManifest = typeof ARTIFACT_STORAGE_CLOSURE_MANIFEST;

function exactlyMatchesManifest(candidate: unknown, expected: unknown): boolean {
  if (expected === null || typeof expected !== 'object') return Object.is(candidate, expected);
  if (candidate === null || typeof candidate !== 'object') return false;
  if (Array.isArray(expected)) {
    return (
      Array.isArray(candidate) &&
      candidate.length === expected.length &&
      expected.every((entry, index) => exactlyMatchesManifest(candidate[index], entry))
    );
  }
  if (Array.isArray(candidate)) return false;
  const expectedKeys = Reflect.ownKeys(expected);
  const candidateKeys = Reflect.ownKeys(candidate);
  return (
    candidateKeys.length === expectedKeys.length &&
    expectedKeys.every(
      (key) =>
        candidateKeys.includes(key) &&
        exactlyMatchesManifest(
          (candidate as Record<PropertyKey, unknown>)[key],
          (expected as Record<PropertyKey, unknown>)[key],
        ),
    )
  );
}

export function assertArtifactStorageClosureManifest(
  candidate: unknown,
): asserts candidate is ArtifactStorageClosureManifest {
  if (!exactlyMatchesManifest(candidate, ARTIFACT_STORAGE_CLOSURE_MANIFEST)) {
    throw new TypeError('Artifact Storage closure manifest is invalid.');
  }
}

type ExactType<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
const ARTIFACT_RESPONSE_LIMIT_STATIC_MATCH: ExactType<
  typeof MAX_ARTIFACT_RESPONSE_BYTES,
  typeof MAX_RESPONSE_BYTES
> = true;
const ARTIFACT_REQUEST_ID_LIMIT_STATIC_MATCH: ExactType<
  typeof MAX_ARTIFACT_REQUEST_ID_BYTES,
  typeof MAX_REQUEST_ID_BYTES
> = true;
void ARTIFACT_RESPONSE_LIMIT_STATIC_MATCH;
void ARTIFACT_REQUEST_ID_LIMIT_STATIC_MATCH;

function assertArtifactTransportLimits(): void {
  if (
    MAX_ARTIFACT_RESPONSE_BYTES !== MAX_RESPONSE_BYTES ||
    MAX_ARTIFACT_REQUEST_ID_BYTES !== MAX_REQUEST_ID_BYTES
  ) {
    throw new TypeError('Artifact and bounded transport wire limits must remain equal.');
  }
}

function hasExactOwnKeys(value: object, allowedKeys: readonly string[]): boolean {
  const ownKeys = Reflect.ownKeys(value);
  return (
    ownKeys.length === allowedKeys.length &&
    ownKeys.every((key) => typeof key === 'string' && allowedKeys.includes(key))
  );
}

function validateDependencies(raw: unknown): ArtifactInspectorDependencies {
  if (
    raw === null ||
    typeof raw !== 'object' ||
    Array.isArray(raw) ||
    Reflect.ownKeys(raw).some(
      (key) =>
        typeof key !== 'string' || !(ARTIFACT_DEPENDENCY_KEYS as readonly string[]).includes(key),
    )
  ) {
    throw new TypeError('Artifact registration configuration is invalid.');
  }
  const dependencies = raw as Record<string, unknown>;
  if (
    typeof dependencies.resolveAuthorizedArtifact !== 'function' ||
    typeof dependencies.readVersionedRange !== 'function' ||
    typeof dependencies.now !== 'function' ||
    (dependencies.emitOperationalEvent !== undefined &&
      typeof dependencies.emitOperationalEvent !== 'function') ||
    (dependencies.emitInspectionReceipt !== undefined &&
      typeof dependencies.emitInspectionReceipt !== 'function')
  ) {
    throw new TypeError('Artifact registration configuration is invalid.');
  }
  return Object.freeze({
    resolveAuthorizedArtifact:
      dependencies.resolveAuthorizedArtifact as ArtifactInspectorDependencies['resolveAuthorizedArtifact'],
    readVersionedRange:
      dependencies.readVersionedRange as ArtifactInspectorDependencies['readVersionedRange'],
    now: dependencies.now as ArtifactInspectorDependencies['now'],
    ...(dependencies.emitOperationalEvent === undefined
      ? {}
      : {
          emitOperationalEvent: dependencies.emitOperationalEvent as NonNullable<
            ArtifactInspectorDependencies['emitOperationalEvent']
          >,
        }),
    ...(dependencies.emitInspectionReceipt === undefined
      ? {}
      : {
          emitInspectionReceipt: dependencies.emitInspectionReceipt as NonNullable<
            ArtifactInspectorDependencies['emitInspectionReceipt']
          >,
        }),
  });
}

function validateConfig(
  raw: ArtifactMcpRegistrationConfig,
  principalRef: string,
): Readonly<ArtifactMcpRegistrationConfig> {
  try {
    if (
      raw === null ||
      typeof raw !== 'object' ||
      Array.isArray(raw) ||
      !hasExactOwnKeys(raw, ARTIFACT_REGISTRATION_CONFIG_KEYS)
    ) {
      throw new TypeError('invalid');
    }
    const dependencies = validateDependencies(raw.dependencies);
    const context = createArtifactInspectorTrustedContext({
      principalRef,
      inspectorClientRef: raw.inspectorClientRef,
      inspectorCapabilityRef: raw.inspectorCapabilityRef,
      verifierAudience: raw.verifierAudience,
      policyVersion: raw.policyVersion,
      inspectorDeploymentGitCoordinate: raw.inspectorDeploymentGitCoordinate,
    });
    if (context.inspectorClientRef === context.inspectorCapabilityRef.ref) {
      throw new TypeError('invalid');
    }
    return Object.freeze({
      dependencies,
      inspectorClientRef: context.inspectorClientRef,
      inspectorCapabilityRef: Object.freeze({ ...context.inspectorCapabilityRef }),
      verifierAudience: context.verifierAudience,
      policyVersion: context.policyVersion,
      inspectorDeploymentGitCoordinate: context.inspectorDeploymentGitCoordinate,
    });
  } catch {
    throw new TypeError('Artifact registration configuration is invalid.');
  }
}

export function createArtifactRequestCorrelationRef(requestId: string | number): string {
  const digest = createHash('sha256').update(JSON.stringify(requestId), 'utf8').digest('hex');
  return `mcp_req:${digest}`;
}

const READ_ONLY_ANNOTATIONS = Object.freeze({
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
});

export async function executeArtifactOperationWithDeadline<T>(
  operation: () => Promise<T>,
  signal: AbortSignal,
): Promise<T | ReturnType<typeof createArtifactInspectionError>> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let removeAbortListener: (() => void) | undefined;

  const operationOutcome = Promise.resolve()
    .then(operation)
    .then(
      (output) => ({ kind: 'output' as const, output }),
      () => ({
        kind: 'output' as const,
        output: createArtifactInspectionError('INTERNAL_ERROR'),
      }),
    );
  const deadlineOutcome = new Promise<{ readonly kind: 'deadline' }>((resolve) => {
    timer = setTimeout(() => resolve({ kind: 'deadline' }), MAX_ARTIFACT_TOOL_EXECUTION_MS);
  });
  const abortOutcome = new Promise<{ readonly kind: 'deadline' }>((resolve) => {
    const onAbort = () => resolve({ kind: 'deadline' });
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener('abort', onAbort, { once: true });
    removeAbortListener = () => signal.removeEventListener('abort', onAbort);
  });

  try {
    const outcome = await Promise.race([operationOutcome, deadlineOutcome, abortOutcome]);
    return outcome.kind === 'output'
      ? outcome.output
      : createArtifactInspectionError('DEADLINE_EXCEEDED');
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    removeAbortListener?.();
  }
}

interface OperationScopedObserverGate {
  readonly dependencies: ArtifactInspectorDependencies;
  close(): void;
}

function createOperationScopedObserverGate(
  dependencies: ArtifactInspectorDependencies,
): OperationScopedObserverGate {
  let open = true;
  const gatedDependencies: ArtifactInspectorDependencies = {
    resolveAuthorizedArtifact: (...args) => dependencies.resolveAuthorizedArtifact(...args),
    readVersionedRange: (...args) => dependencies.readVersionedRange(...args),
    now: () => dependencies.now(),
    ...(dependencies.emitOperationalEvent === undefined
      ? {}
      : {
          emitOperationalEvent: (event: ArtifactInspectorOperationalEvent): void => {
            if (!open) return;
            try {
              dependencies.emitOperationalEvent?.(event);
            } catch {
              // Observer failures must never affect the registered operation.
            }
          },
        }),
    ...(dependencies.emitInspectionReceipt === undefined
      ? {}
      : {
          emitInspectionReceipt: (
            receipt: Parameters<
              NonNullable<ArtifactInspectorDependencies['emitInspectionReceipt']>
            >[0],
          ): void => {
            if (!open) return;
            try {
              dependencies.emitInspectionReceipt?.(receipt);
            } catch {
              // Observer failures must never affect the registered operation.
            }
          },
        }),
  };
  return {
    dependencies: gatedDependencies,
    close(): void {
      open = false;
    },
  };
}

function isFixedDeadlineExceededOutput(value: unknown): boolean {
  if (value === null || typeof value !== 'object') return false;
  const candidate = value as {
    readonly ok?: unknown;
    readonly error?: {
      readonly code?: unknown;
      readonly message?: unknown;
      readonly retryable?: unknown;
    };
  };
  const fixed = createArtifactInspectionError('DEADLINE_EXCEEDED');
  return (
    candidate.ok === fixed.ok &&
    candidate.error?.code === fixed.error.code &&
    candidate.error.message === fixed.error.message &&
    candidate.error.retryable === fixed.error.retryable
  );
}

function emitRegistrationDeadlineEvent(
  dependencies: ArtifactInspectorDependencies,
  operation: ArtifactInspectionOperation,
  context: ArtifactInspectorTrustedContext,
  startedAtMs: number,
): void {
  const measuredElapsedMs = performance.now() - startedAtMs;
  const elapsedMs = Number.isFinite(measuredElapsedMs)
    ? Math.min(MAX_ARTIFACT_TOOL_EXECUTION_MS, Math.max(0, measuredElapsedMs))
    : 0;
  const event: ArtifactInspectorOperationalEvent = Object.freeze({
    operation,
    resultClass: 'DEADLINE_EXCEEDED',
    ...(context.requestCorrelationId === undefined
      ? {}
      : { requestCorrelationId: context.requestCorrelationId }),
    elapsedMs,
  });
  try {
    dependencies.emitOperationalEvent?.(event);
  } catch {
    // Registration telemetry must never affect the fixed deadline output.
  }
}

async function executeRegisteredArtifactOperation<T>(
  dependencies: ArtifactInspectorDependencies,
  operation: ArtifactInspectionOperation,
  context: ArtifactInspectorTrustedContext,
  signal: AbortSignal,
  inspect: (inspector: ReturnType<typeof createArtifactInspector>) => Promise<T>,
): Promise<T | ReturnType<typeof createArtifactInspectionError>> {
  const startedAtMs = performance.now();
  const gate = createOperationScopedObserverGate(dependencies);
  let output: T | ReturnType<typeof createArtifactInspectionError>;
  try {
    const inspector = createArtifactInspector(gate.dependencies);
    output = await executeArtifactOperationWithDeadline(() => inspect(inspector), signal);
  } finally {
    gate.close();
  }
  if (isFixedDeadlineExceededOutput(output)) {
    emitRegistrationDeadlineEvent(dependencies, operation, context, startedAtMs);
  }
  return output;
}

export interface PreparedArtifactMcpRegistration {
  register(server: McpServer): void;
}

export function prepareArtifactMcpRegistration(
  rawConfig: ArtifactMcpRegistrationConfig,
  principalRef: string,
): PreparedArtifactMcpRegistration {
  assertArtifactTransportLimits();
  assertArtifactStorageClosureManifest(ARTIFACT_STORAGE_CLOSURE_MANIFEST);
  const config = validateConfig(rawConfig, principalRef);
  const registeredOperations = new Set<string>();

  const trustedContext = (requestId: string | number) =>
    createArtifactInspectorTrustedContext({
      principalRef,
      inspectorClientRef: config.inspectorClientRef,
      inspectorCapabilityRef: config.inspectorCapabilityRef,
      verifierAudience: config.verifierAudience,
      policyVersion: config.policyVersion,
      inspectorDeploymentGitCoordinate: config.inspectorDeploymentGitCoordinate,
      requestCorrelationId: createArtifactRequestCorrelationRef(requestId),
    });

  return Object.freeze({
    register(server: McpServer): void {
      for (const operation of ARTIFACT_STORAGE_CLOSURE_MANIFEST.operations) {
        if (registeredOperations.has(operation.name)) {
          throw new TypeError('Artifact tool registration may run only once.');
        }
        registeredOperations.add(operation.name);
        switch (operation.name) {
          case 'artifact_stat':
            server.registerTool(
              ARTIFACT_STAT_TOOL.name,
              {
                title: 'Inspect artifact metadata',
                description:
                  'Returns bounded integrity metadata for one authorized opaque artifact.',
                inputSchema: ARTIFACT_STAT_TOOL.inputSchema,
                outputSchema: ARTIFACT_STAT_TOOL.outputSchema,
                annotations: READ_ONLY_ANNOTATIONS,
              },
              async (input, context) => {
                const operationContext = trustedContext(context.mcpReq.id);
                return createArtifactInspectionMcpResult(
                  await executeRegisteredArtifactOperation(
                    config.dependencies,
                    'artifact_stat',
                    operationContext,
                    context.mcpReq.signal,
                    (inspector) => inspector.artifactStat(operationContext, input),
                  ),
                );
              },
            );
            break;
          case 'artifact_read_range':
            server.registerTool(
              ARTIFACT_READ_RANGE_TOOL.name,
              {
                title: 'Read an artifact byte range',
                description:
                  'Returns one bounded UTF-8 range after exact-version chunk and Merkle verification.',
                inputSchema: ARTIFACT_READ_RANGE_TOOL.inputSchema,
                outputSchema: ARTIFACT_READ_RANGE_TOOL.outputSchema,
                annotations: READ_ONLY_ANNOTATIONS,
              },
              async (input, context) => {
                const operationContext = trustedContext(context.mcpReq.id);
                return createArtifactInspectionMcpResult(
                  await executeRegisteredArtifactOperation(
                    config.dependencies,
                    'artifact_read_range',
                    operationContext,
                    context.mcpReq.signal,
                    (inspector) => inspector.artifactReadRange(operationContext, input),
                  ),
                );
              },
            );
            break;
          case 'artifact_read_lines':
            server.registerTool(
              ARTIFACT_READ_LINES_TOOL.name,
              {
                title: 'Read artifact lines',
                description:
                  'Returns bounded UTF-8 lines after exact-version complete-source verification.',
                inputSchema: ARTIFACT_READ_LINES_TOOL.inputSchema,
                outputSchema: ARTIFACT_READ_LINES_TOOL.outputSchema,
                annotations: READ_ONLY_ANNOTATIONS,
              },
              async (input, context) => {
                const operationContext = trustedContext(context.mcpReq.id);
                return createArtifactInspectionMcpResult(
                  await executeRegisteredArtifactOperation(
                    config.dependencies,
                    'artifact_read_lines',
                    operationContext,
                    context.mcpReq.signal,
                    (inspector) => inspector.artifactReadLines(operationContext, input),
                  ),
                );
              },
            );
            break;
        }
      }
      const actual = [...registeredOperations].toSorted();
      const expected = ARTIFACT_STORAGE_CLOSURE_MANIFEST.operations
        .map((operation) => operation.name)
        .toSorted();
      if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        throw new TypeError('Artifact registration does not match the Storage closure manifest.');
      }
    },
  });
}
