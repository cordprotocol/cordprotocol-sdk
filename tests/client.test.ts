import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CordProtocol } from '../src/client.js';
import { generateKeyPair, issueCredential } from '../src/issuer.js';
import type { AgentRegistration } from '../src/registry.js';

function stubFetch(response: Partial<Response>): void {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response as Response));
}

function mockReg(agentId = 'bot'): AgentRegistration {
  return {
    id: 'r1',
    agentId,
    publicKey: 'pk',
    issuedTo: 'Acme',
    registeredAt: '2024-01-01T00:00:00.000Z',
    credentialCount: 1,
    active: true,
  };
}

// ─── issueCredential ──────────────────────────────────────────────────────────

describe('CordProtocol.issueCredential', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('issues a credential without a registry call when registry is false (default)', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const kp = await generateKeyPair();
    const cord = new CordProtocol();

    const cred = await cord.issueCredential(
      { agentId: 'bot', issuedTo: 'Acme', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );

    expect(cred.agentId).toBe('bot');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('POSTs to the registry after issuance when registry: true', async () => {
    const kp = await generateKeyPair();
    stubFetch({ ok: true, json: async () => mockReg() });

    const cord = new CordProtocol({ registry: true });
    const cred = await cord.issueCredential(
      { agentId: 'bot', issuedTo: 'Acme', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );

    expect(cred.agentId).toBe('bot');
    expect(cred.signature).toBeTruthy();
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(
      'https://api.cordprotocol.dev/v1/registry/agents',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('returns the credential even when the registry POST fails with a network error', async () => {
    const kp = await generateKeyPair();
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new Error('Network error')));

    const cord = new CordProtocol({ registry: true });
    const cred = await cord.issueCredential(
      { agentId: 'bot', issuedTo: 'Acme', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );

    expect(cred.agentId).toBe('bot');
  });

  it('returns the credential even when the registry returns a non-ok HTTP status', async () => {
    const kp = await generateKeyPair();
    stubFetch({ ok: false, status: 500, statusText: 'Internal Server Error' });

    const cord = new CordProtocol({ registry: true });
    const cred = await cord.issueCredential(
      { agentId: 'bot', issuedTo: 'Acme', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );

    expect(cred.agentId).toBe('bot');
  });
});

// ─── verifyCredential ─────────────────────────────────────────────────────────

describe('CordProtocol.verifyCredential', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('returns valid for a fresh credential when no apiKey is configured', async () => {
    const kp = await generateKeyPair();
    const cred = await issueCredential(
      { agentId: 'bot', issuedTo: 'Acme', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );

    const cord = new CordProtocol();
    const result = await cord.verifyCredential(cred);

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('checks revocation status when apiKey is provided and credential is locally valid', async () => {
    const kp = await generateKeyPair();
    const cred = await issueCredential(
      { agentId: 'bot', issuedTo: 'Acme', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );
    stubFetch({ ok: true, json: async () => ({ revoked: false }) });

    const cord = new CordProtocol({ apiKey: 'test-key' });
    const result = await cord.verifyCredential(cred);

    expect(result.valid).toBe(true);
    expect(fetch).toHaveBeenCalledWith(
      `https://api.cordprotocol.dev/v1/credentials/${cred.id}/status`,
    );
  });

  it('marks the credential invalid when revocation check says revoked', async () => {
    const kp = await generateKeyPair();
    const cred = await issueCredential(
      { agentId: 'bot', issuedTo: 'Acme', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );
    stubFetch({ ok: true, json: async () => ({ revoked: true, reason: 'compromised' }) });

    const cord = new CordProtocol({ apiKey: 'test-key' });
    const result = await cord.verifyCredential(cred);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('revoked'))).toBe(true);
    expect(result.errors.some((e) => e.includes('compromised'))).toBe(true);
  });

  it('returns the local verification result when the revocation check throws', async () => {
    const kp = await generateKeyPair();
    const cred = await issueCredential(
      { agentId: 'bot', issuedTo: 'Acme', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new Error('Network error')));

    const cord = new CordProtocol({ apiKey: 'test-key' });
    const result = await cord.verifyCredential(cred);

    // Local signature check should still pass
    expect(result.valid).toBe(true);
  });

  it('does not call the revocation endpoint for locally invalid credentials', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const kp = await generateKeyPair();
    const cred = await issueCredential(
      { agentId: 'bot', issuedTo: 'Acme', permissions: ['read:data'] },
      kp.privateKeyBase64,
    );
    // Tamper the credential to make it locally invalid
    const tampered = { ...cred, agentId: 'evil-bot' };

    const cord = new CordProtocol({ apiKey: 'test-key' });
    const result = await cord.verifyCredential(tampered);

    expect(result.valid).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
  });
});

// ─── revokeCredential ─────────────────────────────────────────────────────────

describe('CordProtocol.revokeCredential', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('throws if apiKey is not configured', async () => {
    const cord = new CordProtocol();
    await expect(cord.revokeCredential('cred-id', 'agent-id')).rejects.toThrow(
      'apiKey is required',
    );
  });

  it('POSTs to the revoke endpoint with the Authorization header', async () => {
    stubFetch({ ok: true });

    const cord = new CordProtocol({ apiKey: 'my-api-key' });
    await cord.revokeCredential('cred-id', 'agent-id', 'security issue');

    expect(fetch).toHaveBeenCalledWith(
      'https://api.cordprotocol.dev/v1/credentials/revoke',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ Authorization: 'Bearer my-api-key' }),
      }),
    );
  });
});

// ─── lookupAgent ──────────────────────────────────────────────────────────────

describe('CordProtocol.lookupAgent', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('returns the agent registration when found', async () => {
    const reg = mockReg('search-bot');
    stubFetch({ ok: true, json: async () => reg });

    const cord = new CordProtocol();
    const result = await cord.lookupAgent('search-bot');

    expect(result).toEqual(reg);
  });

  it('returns null when the agent is not found', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce({ ok: false, status: 404 } as Response));

    const cord = new CordProtocol();
    const result = await cord.lookupAgent('unknown-agent');

    expect(result).toBeNull();
  });
});
