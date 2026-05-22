import { describe, expect, it } from 'vitest';
import { generateKeyPair, issueCredential } from '../src/issuer.js';
import {
  verifyCredential,
  isExpired,
  hasPermission,
  validateCredentialSchema,
} from '../src/verifier.js';
import type { AgentCredential } from '../src/credential.js';

/** Helper: issue a valid credential expiring 24h from now */
async function freshCredential(
  overrides: Partial<Parameters<typeof issueCredential>[0]> = {},
): Promise<{ credential: AgentCredential; kp: Awaited<ReturnType<typeof generateKeyPair>> }> {
  const kp = await generateKeyPair();
  const credential = await issueCredential(
    {
      agentId: 'test-agent',
      issuedTo: 'Test Org',
      permissions: ['read:data', 'write:orders'],
      expiresIn: '24h',
      ...overrides,
    },
    kp.privateKeyBase64,
  );
  return { credential, kp };
}

// ─── verifyCredential ─────────────────────────────────────────────────────────

describe('verifyCredential', () => {
  it('accepts a freshly issued valid credential', async () => {
    const { credential } = await freshCredential();
    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.credential).toBeDefined();
  });

  it('accepts a base64-encoded credential', async () => {
    const { credential } = await freshCredential();
    const encoded = Buffer.from(JSON.stringify(credential)).toString('base64');
    const result = await verifyCredential(encoded);
    expect(result.valid).toBe(true);
  });

  it('rejects an expired but otherwise valid credential', async () => {
    const kp = await generateKeyPair();
    // Issue with a past ISO timestamp — the credential is signed correctly
    // but will fail the expiry check
    const past = '2020-06-15T12:00:00.000Z';
    const credential = await issueCredential(
      {
        agentId: 'agent',
        issuedTo: 'Bob',
        permissions: ['read:data'],
        expiresIn: past,
      },
      kp.privateKeyBase64,
    );
    const result = await verifyCredential(credential);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('expired'))).toBe(true);
    // Signature should still be valid on an expired credential
    expect(result.errors.some((e) => e.includes('Signature'))).toBe(false);
  });

  it('rejects a credential with a tampered agentId', async () => {
    const { credential } = await freshCredential();
    const tampered: AgentCredential = { ...credential, agentId: 'evil-bot' };
    const result = await verifyCredential(tampered);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(
      'Signature verification failed — credential may have been tampered with',
    );
  });

  it('rejects a credential with extra permissions injected', async () => {
    const { credential } = await freshCredential();
    const tampered: AgentCredential = {
      ...credential,
      permissions: [...credential.permissions, 'execute:code'],
    };
    const result = await verifyCredential(tampered);
    expect(result.valid).toBe(false);
  });

  it('rejects a credential with a tampered expiresAt', async () => {
    const { credential } = await freshCredential();
    const tampered: AgentCredential = {
      ...credential,
      // Push expiry far into the future — should fail sig check
      expiresAt: '2099-01-01T00:00:00.000Z',
    };
    const result = await verifyCredential(tampered);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(
      'Signature verification failed — credential may have been tampered with',
    );
  });

  it('rejects a credential with a corrupted signature', async () => {
    const { credential } = await freshCredential();
    const tampered: AgentCredential = {
      ...credential,
      signature: Buffer.from('not-a-real-signature').toString('base64'),
    };
    const result = await verifyCredential(tampered);
    expect(result.valid).toBe(false);
  });

  it('rejects a credential signed by a different key', async () => {
    const { credential } = await freshCredential();
    const otherKp = await generateKeyPair();
    // Swap the public key so the sig is verified against the wrong key
    const spoofed: AgentCredential = {
      ...credential,
      issuerPublicKey: otherKp.publicKeyBase64,
    };
    const result = await verifyCredential(spoofed);
    expect(result.valid).toBe(false);
  });

  it('rejects malformed base64 input', async () => {
    const result = await verifyCredential('!!! not base64 !!!');
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('Failed to decode credential');
  });

  it('rejects valid base64 that is not a credential JSON', async () => {
    const notCred = Buffer.from(JSON.stringify({ hello: 'world' })).toString('base64');
    const result = await verifyCredential(notCred);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });
});

// ─── isExpired ────────────────────────────────────────────────────────────────

describe('isExpired', () => {
  it('returns false for a credential that expires in the future', async () => {
    const { credential } = await freshCredential();
    expect(isExpired(credential)).toBe(false);
  });

  it('returns true for a credential with a past expiresAt', async () => {
    const { credential } = await freshCredential();
    expect(isExpired({ ...credential, expiresAt: '2000-01-01T00:00:00.000Z' })).toBe(true);
  });
});

// ─── hasPermission ────────────────────────────────────────────────────────────

describe('hasPermission', () => {
  it('returns true when the scope is in the permissions array', async () => {
    const { credential } = await freshCredential();
    expect(hasPermission(credential, 'read:data')).toBe(true);
    expect(hasPermission(credential, 'write:orders')).toBe(true);
  });

  it('returns false when the scope is not present', async () => {
    const { credential } = await freshCredential();
    expect(hasPermission(credential, 'execute:code')).toBe(false);
    expect(hasPermission(credential, 'spend:1000')).toBe(false);
  });
});

// ─── validateCredentialSchema ─────────────────────────────────────────────────

describe('validateCredentialSchema', () => {
  it('returns no errors for a structurally valid credential', async () => {
    const { credential } = await freshCredential();
    expect(validateCredentialSchema(credential)).toHaveLength(0);
  });

  it('returns an error for null', () => {
    expect(validateCredentialSchema(null)).toContain('Credential must be a non-null object');
  });

  it('returns an error for a primitive', () => {
    expect(validateCredentialSchema('string')).toContain('Credential must be a non-null object');
  });

  it('returns errors for each missing required string field', () => {
    const errors = validateCredentialSchema({ id: 'only-id' });
    expect(errors.length).toBeGreaterThan(3);
  });

  it('returns an error when permissions is not an array', () => {
    const { credential } = { credential: { id: 'x', agentId: 'y', issuedTo: 'z',
      issuedAt: '2024-01-01T00:00:00.000Z', expiresAt: '2025-01-01T00:00:00.000Z',
      attestationHash: 'h', issuerPublicKey: 'k', signature: 's', permissions: 'bad' } };
    const errors = validateCredentialSchema(credential);
    expect(errors.some((e) => e.includes('permissions'))).toBe(true);
  });
});
