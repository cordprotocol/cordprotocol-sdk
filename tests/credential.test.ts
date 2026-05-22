import { describe, expect, it } from 'vitest';
import { serializePayload } from '../src/credential.js';
import type { CredentialPayload } from '../src/credential.js';

const basePayload: CredentialPayload = {
  id: 'test-uuid-1234',
  agentId: 'agent-001',
  issuedTo: 'Acme Corp',
  issuedAt: '2024-01-01T00:00:00.000Z',
  expiresAt: '2024-01-02T00:00:00.000Z',
  permissions: ['read:data', 'write:orders'],
  attestationHash: 'abc123==',
  issuerPublicKey: 'pubkeybase64==',
};

describe('serializePayload', () => {
  it('produces a valid JSON string', () => {
    const result = serializePayload(basePayload);
    expect(() => JSON.parse(result)).not.toThrow();
  });

  it('produces deterministic output regardless of property insertion order', () => {
    const reversed: CredentialPayload = {
      issuerPublicKey: basePayload.issuerPublicKey,
      attestationHash: basePayload.attestationHash,
      permissions: basePayload.permissions,
      expiresAt: basePayload.expiresAt,
      issuedAt: basePayload.issuedAt,
      issuedTo: basePayload.issuedTo,
      agentId: basePayload.agentId,
      id: basePayload.id,
    };

    expect(serializePayload(basePayload)).toBe(serializePayload(reversed));
  });

  it('includes all payload fields in the output', () => {
    const result = serializePayload(basePayload);
    const parsed = JSON.parse(result) as Record<string, unknown>;

    expect(parsed.id).toBe(basePayload.id);
    expect(parsed.agentId).toBe(basePayload.agentId);
    expect(parsed.issuedTo).toBe(basePayload.issuedTo);
    expect(parsed.permissions).toEqual(basePayload.permissions);
    expect(parsed.attestationHash).toBe(basePayload.attestationHash);
    expect(parsed.issuerPublicKey).toBe(basePayload.issuerPublicKey);
  });

  it('serializes keys in sorted (alphabetical) order', () => {
    const result = serializePayload(basePayload);
    const keys = Object.keys(JSON.parse(result) as object);
    expect(keys).toEqual([...keys].sort());
  });

  it('produces different output for different permission arrays', () => {
    const p1 = { ...basePayload, permissions: ['read:data'] };
    const p2 = { ...basePayload, permissions: ['read:data', 'write:orders'] };
    expect(serializePayload(p1)).not.toBe(serializePayload(p2));
  });
});
