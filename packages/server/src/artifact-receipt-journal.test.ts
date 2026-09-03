import type { ArtifactInspectionReceipt } from '@supabase-user-mcp/contracts';
import { describe, expect, it } from 'vitest';

import {
  appendArtifactInspectionReceipt,
  artifactInspectionReceiptSha256,
  ARTIFACT_RECEIPT_JOURNAL_PROFILE_VERSION,
  ArtifactReceiptJournalError,
  type ArtifactReceiptJournal,
  canonicalArtifactInspectionReceiptBytes,
} from './artifact-receipt-journal.js';

const GOLDEN_RECEIPT: ArtifactInspectionReceipt = {
  receiptSchemaVersion: 'artifact-inspection-receipt/0.2',
  verifierAudience: 'verifier:synthetic',
  principalRef: 'principal:synthetic',
  principalBinding: 'session_derived',
  inspectorClientRef: 'client:approved',
  inspectorClientBinding: 'approved',
  inspectorCapabilityRef: { capability: 'artifact:inspect', ref: 'grant:approved' },
  artifactId: 'art_0000000000000000000001',
  objectVersionRef: 'ov_0000000000000000000001',
  sourceSha256: '1'.repeat(64),
  merkleRoot: '2'.repeat(64),
  analyzerProfileId: 'text/markdown',
  analyzerProfileVersion: 'artifact-inspector-s2-0.1',
  policyVersion: 'artifact-policy-0.1',
  inspectorDeploymentGitCoordinate: 'a'.repeat(40),
  recordedAt: '2026-09-02T00:00:00.000Z',
  operationDetail: {
    operation: 'artifact_search_exact',
    queryLength: 6,
    maxHits: 2,
    returnedHits: [
      {
        returnedRange: { offset: 3, length: 6 },
        returnedByteSha256: '3'.repeat(64),
      },
      {
        returnedRange: { offset: 12, length: 6 },
        returnedByteSha256: '4'.repeat(64),
      },
    ],
  },
  resultOrErrorClass: { kind: 'result' },
};

const GOLDEN_CANONICAL_JSON =
  '{"analyzerProfileId":"text/markdown","analyzerProfileVersion":"artifact-inspector-s2-0.1","artifactId":"art_0000000000000000000001","inspectorCapabilityRef":{"capability":"artifact:inspect","ref":"grant:approved"},"inspectorClientBinding":"approved","inspectorClientRef":"client:approved","inspectorDeploymentGitCoordinate":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","merkleRoot":"2222222222222222222222222222222222222222222222222222222222222222","objectVersionRef":"ov_0000000000000000000001","operationDetail":{"maxHits":2,"operation":"artifact_search_exact","queryLength":6,"returnedHits":[{"returnedByteSha256":"3333333333333333333333333333333333333333333333333333333333333333","returnedRange":{"length":6,"offset":3}},{"returnedByteSha256":"4444444444444444444444444444444444444444444444444444444444444444","returnedRange":{"length":6,"offset":12}}]},"policyVersion":"artifact-policy-0.1","principalBinding":"session_derived","principalRef":"principal:synthetic","receiptSchemaVersion":"artifact-inspection-receipt/0.2","recordedAt":"2026-09-02T00:00:00.000Z","resultOrErrorClass":{"kind":"result"},"sourceSha256":"1111111111111111111111111111111111111111111111111111111111111111","verifierAudience":"verifier:synthetic"}';

export function goldenReceipt(): ArtifactInspectionReceipt {
  return structuredClone(GOLDEN_RECEIPT);
}

describe('artifact-receipt-journal canonical receipt digest', () => {
  it('matches the hardcoded canonical UTF-8 bytes and SHA-256 golden vector', () => {
    expect(ARTIFACT_RECEIPT_JOURNAL_PROFILE_VERSION).toBe('artifact-receipt-journal/0.1');
    const receipt = goldenReceipt();
    const bytes = canonicalArtifactInspectionReceiptBytes(receipt);
    expect(new TextDecoder().decode(bytes)).toBe(GOLDEN_CANONICAL_JSON);
    expect(artifactInspectionReceiptSha256(receipt)).toBe(
      'b8f634a1a8bb26ddd23a1a85a7c3a76dd760b69f8b4d9b0c5d13572f1fb44ed2',
    );
  });

  it('is byte-identical and digest-identical across repeated calls and key insertion order', () => {
    const receipt = goldenReceipt();
    const reordered = Object.fromEntries(Object.entries(receipt).toReversed());
    expect(canonicalArtifactInspectionReceiptBytes(receipt)).toEqual(
      canonicalArtifactInspectionReceiptBytes(reordered),
    );
    expect(artifactInspectionReceiptSha256(receipt)).toBe(artifactInspectionReceiptSha256(receipt));
    expect(artifactInspectionReceiptSha256(reordered)).toBe(
      artifactInspectionReceiptSha256(receipt),
    );
  });

  it('changes the digest for every top-level and nested receipt field mutation', () => {
    const base = goldenReceipt();
    const expected = artifactInspectionReceiptSha256(base);
    const mutations: Array<(receipt: ArtifactInspectionReceipt) => void> = [
      (receipt) => {
        receipt.verifierAudience = 'verifier:changed';
      },
      (receipt) => {
        receipt.principalRef = 'principal:changed';
      },
      (receipt) => {
        receipt.inspectorClientRef = 'client:changed';
      },
      (receipt) => {
        receipt.inspectorCapabilityRef.ref = 'grant:changed';
      },
      (receipt) => {
        receipt.artifactId = 'art_0000000000000000000002';
      },
      (receipt) => {
        receipt.objectVersionRef = 'ov_0000000000000000000002';
      },
      (receipt) => {
        receipt.sourceSha256 = '5'.repeat(64);
      },
      (receipt) => {
        receipt.merkleRoot = '6'.repeat(64);
      },
      (receipt) => {
        receipt.analyzerProfileId = 'text/plain';
      },
      (receipt) => {
        receipt.analyzerProfileVersion = 'artifact-inspector-s2-0.2';
      },
      (receipt) => {
        receipt.policyVersion = 'artifact-policy-0.2';
      },
      (receipt) => {
        receipt.inspectorDeploymentGitCoordinate = 'b'.repeat(40);
      },
      (receipt) => {
        receipt.recordedAt = '2026-09-02T00:00:01.000Z';
      },
      (receipt) => {
        if (receipt.operationDetail.operation !== 'artifact_search_exact')
          throw new Error('fixture');
        receipt.operationDetail.queryLength = 7;
      },
      (receipt) => {
        if (receipt.operationDetail.operation !== 'artifact_search_exact')
          throw new Error('fixture');
        receipt.operationDetail.maxHits = 3;
      },
      (receipt) => {
        if (receipt.operationDetail.operation !== 'artifact_search_exact')
          throw new Error('fixture');
        const hit = receipt.operationDetail.returnedHits[0];
        if (hit === undefined) throw new Error('fixture');
        hit.returnedRange.offset = 4;
      },
      (receipt) => {
        if (receipt.operationDetail.operation !== 'artifact_search_exact')
          throw new Error('fixture');
        const hit = receipt.operationDetail.returnedHits[0];
        if (hit === undefined) throw new Error('fixture');
        hit.returnedRange.length = 7;
      },
      (receipt) => {
        if (receipt.operationDetail.operation !== 'artifact_search_exact')
          throw new Error('fixture');
        const hit = receipt.operationDetail.returnedHits[0];
        if (hit === undefined) throw new Error('fixture');
        hit.returnedByteSha256 = '7'.repeat(64);
      },
      (receipt) => {
        receipt.resultOrErrorClass = { kind: 'error', errorClass: 'INTEGRITY_FAILURE' };
      },
    ];
    for (const mutate of mutations) {
      const candidate = goldenReceipt();
      mutate(candidate);
      expect(artifactInspectionReceiptSha256(candidate)).not.toBe(expected);
    }
  });

  it('preserves array order in the canonical bytes and digest', () => {
    const first = goldenReceipt();
    const second = goldenReceipt();
    if (
      first.operationDetail.operation !== 'artifact_search_exact' ||
      second.operationDetail.operation !== 'artifact_search_exact'
    ) {
      throw new Error('fixture');
    }
    second.operationDetail.returnedHits.reverse();
    expect(canonicalArtifactInspectionReceiptBytes(second)).not.toEqual(
      canonicalArtifactInspectionReceiptBytes(first),
    );
    expect(artifactInspectionReceiptSha256(second)).not.toBe(
      artifactInspectionReceiptSha256(first),
    );
  });

  it('rejects unsupported JSON values, accessors, toJSON, cycles, and non-plain containers', () => {
    const unsupported: unknown[] = [
      { ...goldenReceipt(), extra: undefined },
      { ...goldenReceipt(), extra: Symbol('no') },
      { ...goldenReceipt(), extra: () => undefined },
      { ...goldenReceipt(), extra: 1n },
      { ...goldenReceipt(), extra: Number.NaN },
      { ...goldenReceipt(), extra: Number.POSITIVE_INFINITY },
      { ...goldenReceipt(), extra: new Date() },
      { ...goldenReceipt(), extra: new (class CustomRecord {})() },
    ];
    const cycle = goldenReceipt() as ArtifactInspectionReceipt & { self?: unknown };
    cycle.self = cycle;
    unsupported.push(cycle);

    let getterCalls = 0;
    const accessor = goldenReceipt() as ArtifactInspectionReceipt & { extra?: unknown };
    Object.defineProperty(accessor, 'extra', {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        throw new Error('accessor-secret-SENTINEL');
      },
    });
    unsupported.push(accessor);

    let toJsonCalls = 0;
    const withToJson = goldenReceipt() as ArtifactInspectionReceipt & { toJSON?: () => unknown };
    Object.defineProperty(withToJson, 'toJSON', {
      enumerable: false,
      value: () => {
        toJsonCalls += 1;
        return {};
      },
    });
    unsupported.push(withToJson);

    const nonordinaryArray = goldenReceipt();
    if (nonordinaryArray.operationDetail.operation !== 'artifact_search_exact') {
      throw new Error('fixture');
    }
    Object.defineProperty(nonordinaryArray.operationDetail.returnedHits, 'extra', {
      enumerable: true,
      value: 'no',
    });
    unsupported.push(nonordinaryArray);

    for (const candidate of unsupported) {
      expect(() => canonicalArtifactInspectionReceiptBytes(candidate)).toThrow(TypeError);
    }
    expect(getterCalls).toBe(0);
    expect(toJsonCalls).toBe(0);
  });
});

describe('artifact-receipt-journal append acknowledgement gate', () => {
  it('calls append exactly once with a frozen safe copy and returns a frozen strict acknowledgement', async () => {
    const receipt = goldenReceipt();
    const digest = artifactInspectionReceiptSha256(receipt);
    const calls: Array<{ receipt: ArtifactInspectionReceipt; digest: string }> = [];
    const journal: ArtifactReceiptJournal = {
      append: async (appendedReceipt, expectedDigest) => {
        calls.push({ receipt: appendedReceipt, digest: expectedDigest });
        expect(appendedReceipt).not.toBe(receipt);
        expect(Object.isFrozen(appendedReceipt)).toBe(true);
        expect(Object.isFrozen(appendedReceipt.operationDetail)).toBe(true);
        return {
          schemaVersion: 'artifact-receipt-journal-ack/0.1',
          receiptSha256: expectedDigest,
          journalRef: 'journal:entry:0001',
        };
      },
    };

    const acknowledgement = await appendArtifactInspectionReceipt(journal, receipt, digest);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.digest).toBe(digest);
    expect(calls[0]?.receipt).toEqual(receipt);
    expect(acknowledgement).toEqual({
      schemaVersion: 'artifact-receipt-journal-ack/0.1',
      receiptSha256: digest,
      journalRef: 'journal:entry:0001',
    });
    expect(Object.isFrozen(acknowledgement)).toBe(true);
  });

  it('rejects throw, malformed, mismatched digest, extra field, and missing ref with one redacted typed error and no retry', async () => {
    const receipt = goldenReceipt();
    const digest = artifactInspectionReceiptSha256(receipt);
    const secret = 'journal-sink-secret-SENTINEL';
    const outcomes: Array<unknown | (() => never)> = [
      () => {
        throw new Error(secret);
      },
      null,
      {},
      {
        schemaVersion: 'artifact-receipt-journal-ack/0.1',
        receiptSha256: '0'.repeat(64),
        journalRef: 'journal:entry:0001',
      },
      {
        schemaVersion: 'artifact-receipt-journal-ack/0.1',
        receiptSha256: digest,
        journalRef: 'journal:entry:0001',
        extra: secret,
      },
      {
        schemaVersion: 'artifact-receipt-journal-ack/0.1',
        receiptSha256: digest,
      },
    ];

    for (const outcome of outcomes) {
      let calls = 0;
      const journal: ArtifactReceiptJournal = {
        append: async () => {
          calls += 1;
          return typeof outcome === 'function' ? outcome() : outcome;
        },
      };
      let caught: unknown;
      try {
        await appendArtifactInspectionReceipt(journal, receipt, digest);
      } catch (error) {
        caught = error;
      }
      expect(calls).toBe(1);
      expect(caught).toBeInstanceOf(ArtifactReceiptJournalError);
      expect(caught).toMatchObject({
        code: 'JOURNAL_APPEND_FAILED',
        message: 'Artifact receipt journal acknowledgement failed.',
      });
      expect(String(caught)).not.toContain(secret);
      expect(JSON.stringify(caught)).not.toContain(secret);
    }
  });

  it('rejects an expected digest that does not match the canonical receipt before append', async () => {
    let calls = 0;
    const journal: ArtifactReceiptJournal = {
      append: async () => {
        calls += 1;
        return {};
      },
    };
    await expect(
      appendArtifactInspectionReceipt(journal, goldenReceipt(), '0'.repeat(64)),
    ).rejects.toMatchObject({ code: 'JOURNAL_APPEND_FAILED' });
    expect(calls).toBe(0);
  });
});
