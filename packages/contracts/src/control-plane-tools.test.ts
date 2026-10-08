import { describe, expect, it } from 'vitest';

import {
  CreateWorkItemInputSchema,
  createControlPlaneToolError,
  MAX_CONTROL_PLANE_BODY_LENGTH,
  MAX_CONTROL_PLANE_METADATA_BYTES,
  PostModelMessageInputSchema,
} from './control-plane-tools.js';

describe('control-plane tool contracts', () => {
  it('applies planning defaults and requires an idempotency key', () => {
    expect(
      CreateWorkItemInputSchema.parse({
        boardSlug: 'synthetic-board',
        title: 'Synthetic item',
        idempotencyKey: 'synthetic-item-001',
      }),
    ).toEqual({
      boardSlug: 'synthetic-board',
      itemKind: 'task',
      title: 'Synthetic item',
      priority: 50,
      status: 'inbox',
      labels: [],
      executionMode: 'either',
      authorityRequired: 'read_only',
      reviewRequired: true,
      idempotencyKey: 'synthetic-item-001',
      metadata: {},
    });
    expect(
      CreateWorkItemInputSchema.safeParse({ boardSlug: 'synthetic-board', title: 'Missing key' })
        .success,
    ).toBe(false);
  });

  it('uses the live planning constraint vocabulary', () => {
    const base = {
      boardSlug: 'synthetic-board',
      title: 'Synthetic item',
      idempotencyKey: 'synthetic-item-002',
    };
    expect(CreateWorkItemInputSchema.safeParse({ ...base, status: 'in_progress' }).success).toBe(
      true,
    );
    expect(CreateWorkItemInputSchema.safeParse({ ...base, status: 'in-progress' }).success).toBe(
      false,
    );
    expect(CreateWorkItemInputSchema.safeParse({ ...base, itemKind: 'decision' }).success).toBe(
      true,
    );
    expect(CreateWorkItemInputSchema.safeParse({ ...base, itemKind: 'feature' }).success).toBe(
      false,
    );
  });

  it('rejects caller identity, authority plumbing, and generic database controls', () => {
    const forbidden = [
      'fromAgent',
      'sourceAgent',
      'principalId',
      'role',
      'sql',
      'schema',
      'table',
      'url',
      'method',
      'apikey',
    ];
    for (const property of forbidden) {
      expect(
        CreateWorkItemInputSchema.safeParse({
          boardSlug: 'synthetic-board',
          title: 'Synthetic item',
          idempotencyKey: 'synthetic-item-003',
          [property]: 'forbidden',
        }).success,
      ).toBe(false);
    }
  });

  it('bounds metadata and message bodies', () => {
    expect(
      CreateWorkItemInputSchema.safeParse({
        boardSlug: 'synthetic-board',
        title: 'Synthetic item',
        idempotencyKey: 'synthetic-item-004',
        metadata: { oversized: 'x'.repeat(MAX_CONTROL_PLANE_METADATA_BYTES) },
      }).success,
    ).toBe(false);
    expect(
      PostModelMessageInputSchema.safeParse({
        toAgent: 'synthetic-agent',
        subject: 'Synthetic message',
        body: 'x'.repeat(MAX_CONTROL_PLANE_BODY_LENGTH + 1),
      }).success,
    ).toBe(false);
  });

  it('rejects invisible and non-ASCII identifier characters', () => {
    expect(
      CreateWorkItemInputSchema.safeParse({
        boardSlug: 'synthetic\u200b-board',
        title: 'Synthetic item',
        idempotencyKey: 'synthetic-item-005',
      }).success,
    ).toBe(false);
    expect(
      PostModelMessageInputSchema.safeParse({
        toAgent: 'synthetic-\u202ewarden',
        subject: 'Synthetic message',
        body: 'Synthetic body',
      }).success,
    ).toBe(false);
  });

  it('publishes stable non-leaking errors', () => {
    expect(createControlPlaneToolError('BOARD_UNAVAILABLE')).toEqual({
      ok: false,
      error: {
        code: 'BOARD_UNAVAILABLE',
        message: 'Board is unavailable.',
        retryable: false,
      },
    });
    expect(createControlPlaneToolError('UPSTREAM_UNAVAILABLE').error.retryable).toBe(true);
  });
});
