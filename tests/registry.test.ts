import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  registerAgent,
  lookupAgent,
  checkRevocationStatus,
  revokeCredential,
} from '../src/registry.js';
import type { AgentRegistration } from '../src/registry.js';

function mockReg(overrides: Partial<AgentRegistration> = {}): AgentRegistration {
  return {
    id: 'reg-1',
    agentId: 'my-agent',
    publicKey: 'pubkey123',
    issuedTo: 'Acme Corp',
    registeredAt: '2024-01-01T00:00:00.000Z',
    credentialCount: 0,
    active: true,
    ...overrides,
  };
}

function okResponse(body: unknown): Response {
  return { ok: true, status: 200, json: async () => body } as Response;
}

function errorResponse(status: number, statusText: string): Response {
  return { ok: false, status, statusText } as Response;
}

// ─── registerAgent ────────────────────────────────────────────────────────────

describe('registerAgent', () => {
  beforeEach(() => vi.stubGlobal('fetch', vi.fn()));
  afterEach(() => vi.unstubAllGlobals());

  it('POSTs to the default registry URL and returns the registration', async () => {
    const reg = mockReg();
    vi.mocked(fetch).mockResolvedValueOnce(okResponse(reg));

    const result = await registerAgent('my-agent', 'pubkey123', 'Acme Corp');

    expect(result).toEqual(reg);
    expect(fetch).toHaveBeenCalledWith(
      'https://api.cordprotocol.dev/v1/registry/agents',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('throws on a non-ok response', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(errorResponse(500, 'Internal Server Error'));
    await expect(registerAgent('agent', 'key', 'Org')).rejects.toThrow('Registry error: 500');
  });

  it('uses a custom apiUrl when provided', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okResponse(mockReg()));
    await registerAgent('a', 'k', 'O', undefined, 'https://custom.api.dev');
    expect(fetch).toHaveBeenCalledWith(
      'https://custom.api.dev/v1/registry/agents',
      expect.anything(),
    );
  });

  it('includes domain in the POST body when provided', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okResponse(mockReg({ domain: 'acme.com' })));
    await registerAgent('a', 'k', 'O', 'acme.com');
    const callBody = JSON.parse((vi.mocked(fetch).mock.calls[0][1] as RequestInit).body as string);
    expect(callBody.domain).toBe('acme.com');
  });
});

// ─── lookupAgent ──────────────────────────────────────────────────────────────

describe('lookupAgent', () => {
  beforeEach(() => vi.stubGlobal('fetch', vi.fn()));
  afterEach(() => vi.unstubAllGlobals());

  it('GETs the agent by ID and returns the registration', async () => {
    const reg = mockReg({ agentId: 'bot-1' });
    vi.mocked(fetch).mockResolvedValueOnce(okResponse(reg));

    const result = await lookupAgent('bot-1');

    expect(result).toEqual(reg);
    expect(fetch).toHaveBeenCalledWith(
      'https://api.cordprotocol.dev/v1/registry/agents/bot-1',
    );
  });

  it('returns null on a 404 response', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({ ok: false, status: 404 } as Response);
    const result = await lookupAgent('unknown-agent');
    expect(result).toBeNull();
  });

  it('throws on non-404 error responses', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(errorResponse(503, 'Service Unavailable'));
    await expect(lookupAgent('agent')).rejects.toThrow('Registry lookup error: 503');
  });
});

// ─── checkRevocationStatus ────────────────────────────────────────────────────

describe('checkRevocationStatus', () => {
  beforeEach(() => vi.stubGlobal('fetch', vi.fn()));
  afterEach(() => vi.unstubAllGlobals());

  it('returns revoked: false for an active credential', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(okResponse({ revoked: false }));
    const result = await checkRevocationStatus('cred-id-1');
    expect(result.revoked).toBe(false);
  });

  it('returns revoked: true with revokedAt and reason when revoked', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      okResponse({ revoked: true, revokedAt: '2024-06-01T00:00:00.000Z', reason: 'compromised' }),
    );
    const result = await checkRevocationStatus('cred-id-2');
    expect(result.revoked).toBe(true);
    expect(result.reason).toBe('compromised');
    expect(result.revokedAt).toBe('2024-06-01T00:00:00.000Z');
  });

  it('throws on a non-ok response', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(errorResponse(500, 'Error'));
    await expect(checkRevocationStatus('id')).rejects.toThrow('Revocation check error: 500');
  });
});

// ─── revokeCredential ─────────────────────────────────────────────────────────

describe('revokeCredential', () => {
  beforeEach(() => vi.stubGlobal('fetch', vi.fn()));
  afterEach(() => vi.unstubAllGlobals());

  it('POSTs to the revoke endpoint with the Authorization header', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({ ok: true } as Response);

    await revokeCredential('cred-id', 'agent-id', 'my-api-key', 'security breach');

    expect(fetch).toHaveBeenCalledWith(
      'https://api.cordprotocol.dev/v1/credentials/revoke',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ Authorization: 'Bearer my-api-key' }),
      }),
    );
  });

  it('throws on a non-ok response', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(errorResponse(401, 'Unauthorized'));
    await expect(revokeCredential('id', 'agent', 'key')).rejects.toThrow('Revocation error: 401');
  });
});
