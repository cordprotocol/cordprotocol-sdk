import { describe, expect, it } from 'vitest';
import { generateKeyPair, issueCredential } from '../src/issuer.js';

describe('generateKeyPair', () => {
  it('returns a key pair with Uint8Array keys', async () => {
    const kp = await generateKeyPair();
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.privateKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey.length).toBe(32);
    expect(kp.privateKey.length).toBe(32);
  });

  it('returns base64-encoded string versions of both keys', async () => {
    const kp = await generateKeyPair();
    // Base64 charset only
    expect(kp.publicKeyBase64).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(kp.privateKeyBase64).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  it('generates a unique key pair each call', async () => {
    const [kp1, kp2] = await Promise.all([generateKeyPair(), generateKeyPair()]);
    expect(kp1.privateKeyBase64).not.toBe(kp2.privateKeyBase64);
    expect(kp1.publicKeyBase64).not.toBe(kp2.publicKeyBase64);
  });
});

describe('issueCredential', () => {
  it('issues a credential with all required fields present', async () => {
    const kp = await generateKeyPair();
    const cred = await issueCredential(
      { agentId: 'bot-1', issuedTo: 'Acme Corp', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );

    expect(cred.id).toBeTruthy();
    expect(cred.agentId).toBe('bot-1');
    expect(cred.issuedTo).toBe('Acme Corp');
    expect(cred.permissions).toEqual(['read:data']);
    expect(cred.issuerPublicKey).toBe(kp.publicKeyBase64);
    expect(cred.signature).toBeTruthy();
    expect(cred.attestationHash).toBeTruthy();
    expect(cred.issuedAt).toBeTruthy();
    expect(cred.expiresAt).toBeTruthy();
  });

  it('embeds the correct issuer public key derived from the private key', async () => {
    const kp = await generateKeyPair();
    const cred = await issueCredential(
      { agentId: 'a', issuedTo: 'b', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );
    expect(cred.issuerPublicKey).toBe(kp.publicKeyBase64);
  });

  it('accepts a Uint8Array private key', async () => {
    const kp = await generateKeyPair();
    const cred = await issueCredential(
      { agentId: 'a', issuedTo: 'b', permissions: ['read:data'] },
      kp.privateKey,
    );
    expect(cred.signature).toBeTruthy();
  });

  it('defaults to a 24h expiry when expiresIn is omitted', async () => {
    const kp = await generateKeyPair();
    const before = Date.now();
    const cred = await issueCredential(
      { agentId: 'a', issuedTo: 'b', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );
    const expiresMs = new Date(cred.expiresAt).getTime();
    expect(expiresMs).toBeGreaterThan(before + 23 * 3_600_000);
    expect(expiresMs).toBeLessThan(before + 25 * 3_600_000);
  });

  it('respects a custom "7d" expiresIn duration', async () => {
    const kp = await generateKeyPair();
    const before = Date.now();
    const cred = await issueCredential(
      { agentId: 'a', issuedTo: 'b', permissions: ['read:data'], expiresIn: '7d' },
      kp.privateKeyBase64,
    );
    const expiresMs = new Date(cred.expiresAt).getTime();
    expect(expiresMs).toBeGreaterThan(before + 6 * 86_400_000);
    expect(expiresMs).toBeLessThan(before + 8 * 86_400_000);
  });

  it('accepts an ISO 8601 timestamp for expiresIn', async () => {
    const kp = await generateKeyPair();
    const future = new Date(Date.now() + 3_600_000).toISOString();
    const cred = await issueCredential(
      { agentId: 'a', issuedTo: 'b', permissions: ['read:data'], expiresIn: future },
      kp.privateKeyBase64,
    );
    expect(cred.expiresAt).toBe(future);
  });

  it('produces different attestation hashes for different attestation data', async () => {
    const kp = await generateKeyPair();
    const [c1, c2] = await Promise.all([
      issueCredential(
        { agentId: 'a', issuedTo: 'b', permissions: ['read:data'], attestationData: 'config-v1' },
        kp.privateKeyBase64,
      ),
      issueCredential(
        { agentId: 'a', issuedTo: 'b', permissions: ['read:data'], attestationData: 'config-v2' },
        kp.privateKeyBase64,
      ),
    ]);
    expect(c1.attestationHash).not.toBe(c2.attestationHash);
  });

  it('produces unique credential IDs on each call', async () => {
    const kp = await generateKeyPair();
    const params = { agentId: 'a', issuedTo: 'b', permissions: ['read:data'] };
    const [c1, c2] = await Promise.all([
      issueCredential(params, kp.privateKeyBase64),
      issueCredential(params, kp.privateKeyBase64),
    ]);
    expect(c1.id).not.toBe(c2.id);
  });

  it('throws on invalid permission scope format', async () => {
    const kp = await generateKeyPair();
    await expect(
      issueCredential(
        { agentId: 'a', issuedTo: 'b', permissions: ['INVALID_SCOPE'] },
        kp.privateKeyBase64,
      ),
    ).rejects.toThrow('Invalid permission scopes');
  });

  it('throws on empty permissions array', async () => {
    const kp = await generateKeyPair();
    await expect(
      issueCredential({ agentId: 'a', issuedTo: 'b', permissions: [] }, kp.privateKeyBase64),
    ).rejects.toThrow('Invalid permission scopes');
  });

  it('throws on invalid expiresIn format', async () => {
    const kp = await generateKeyPair();
    await expect(
      issueCredential(
        { agentId: 'a', issuedTo: 'b', permissions: ['read:data'], expiresIn: 'tomorrow' },
        kp.privateKeyBase64,
      ),
    ).rejects.toThrow('Invalid expiresIn');
  });
});
